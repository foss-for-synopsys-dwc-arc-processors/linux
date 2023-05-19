// SPDX-License-Identifier: GPL-2.0+
//
// Linux cluster performance counters support for ARCv3.
//
// Copyright (C) 2023 Synopsys, Inc. (www.synopsys.com)
//
// Note: use perf with a key "-a" means system-wide collection from all CPUs
// 			to work with cluster PMU

#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/perf_event.h>
#include <linux/percpu.h>
#include <asm/arcregs.h>
#include <asm/stacktrace.h>
#include <asm/cluster.h>
#include <asm/perf_cluster.h>


struct arc_cluster_cpu {
	struct perf_event *events[ARC_CLUSTER_PERF_MAX_COUNTERS];
};

struct arc_cluster_pmu {
	struct pmu pmu;
	int irq;
	int n_counters;
	int	n_events;
	u64	max_period;
	struct cpct_conditions_entry *raw_entry;
	struct arc_cluster_cpu __percpu *pcpu;
};

static struct arc_cluster_pmu *arc_cluster_pmu;
static cpumask_t pmu_cpu;
static struct perf_pmu_events_attr	*attr;
static struct attribute **event_attrs;
static DEFINE_SPINLOCK(cln_prot_op_spinlock);

static void arc_cluster_pmu_read_reg(unsigned int reg, void *data)
{
	unsigned long flags;
	unsigned int val;

	spin_lock_irqsave(&cln_prot_op_spinlock, flags);
	WRITE_AUX(ARC_REG_CLNR_ADDR, reg);
	READ_BCR(ARC_REG_CLNR_DATA, val);
	spin_unlock_irqrestore(&cln_prot_op_spinlock, flags);
	*(unsigned int *)data = val;
}

static void arc_cluster_pmu_write_reg(unsigned int reg, void *data)
{
	unsigned long flags;
	unsigned int val = *(unsigned int *)data;

	spin_lock_irqsave(&cln_prot_op_spinlock, flags);
	WRITE_AUX(ARC_REG_CLNR_ADDR, reg);
	WRITE_AUX(ARC_REG_CLNR_DATA, val);
	spin_unlock_irqrestore(&cln_prot_op_spinlock, flags);
}

/* read counter #idx; note that counter# != event# on ARC cluster! */
static u64 arc_cluster_pmu_read_counter(int idx)
{
    struct cpct_snap snapL, snapH;
	struct cpct_n_config cfg;
	u64 result;
	int number;

	if (WARN_ON_ONCE(idx < 0))
		return 0;

	/*
	 * ARC cluster supports making 'snapshots' of the counters, so we don't
	 * need to care about counters wrapping to 0 underneath our feet
	 */
    number = 8 * idx; // select counter, 0..31

	arc_cluster_pmu_read_reg(SCM_AUX_CPCT_N_CONFIG + number, &cfg);
    cfg.lsn = 1; /* take snapshot */
	arc_cluster_pmu_write_reg(SCM_AUX_CPCT_N_CONFIG + number, &cfg);

	arc_cluster_pmu_read_reg(SCM_AUX_CPCT_N_SNAPH + number, &snapH);
    arc_cluster_pmu_read_reg(SCM_AUX_CPCT_N_SNAPL + number, &snapL);
    result = ((u64)snapH.snap << 32ULL) | (u64)snapL.snap;
	return result;
}

static void arc_cluster_perf_event_update(struct perf_event *event,
				  struct hw_perf_event *hwc, int idx)
{
	u64 prev_raw_count = local64_read(&hwc->prev_count);
	u64 new_raw_count = arc_cluster_pmu_read_counter(idx);
	s64 delta = new_raw_count - prev_raw_count;

	/*
	 * we aren't afraid of hwc->prev_count changing beneath our feet
	 * because there's no way for us to re-enter this function anytime
	 */
	local64_set(&hwc->prev_count, new_raw_count);
	local64_add(delta, &event->count);
	local64_sub(delta, &hwc->period_left);
}

static void arc_cluster_pmu_read(struct perf_event *event)
{
	arc_cluster_perf_event_update(event, &event->hw, event->hw.idx);
}

/* starts all counters */
static void arc_cluster_pmu_enable(struct pmu *pmu)
{
	struct cpct_n_config cfg;
	int ii;
	int number;
	int N = arc_cluster_pmu->n_counters;

	for (ii = 0; ii < N; ii++) {
		number = ii * 8;
		arc_cluster_pmu_read_reg(SCM_AUX_CPCT_N_CONFIG + number, &cfg);
		if (cfg.cc_num != 0xFFFF && cfg.lce == 1) {
			cfg.len = 1;
			arc_cluster_pmu_write_reg(SCM_AUX_CPCT_N_CONFIG + number, &cfg);
		}
	}
}

/* stops all counters */
static void arc_cluster_pmu_disable(struct pmu *pmu)
{
	struct cpct_n_config cfg;
	int ii;
	int number;
	int N = arc_cluster_pmu->n_counters;

	for (ii = 0; ii < N; ii++) {
		number = ii * 8;
		arc_cluster_pmu_read_reg(SCM_AUX_CPCT_N_CONFIG + number, &cfg);
		if (cfg.cc_num != 0xFFFF && cfg.lce == 1) {
			cfg.len = 0;
			arc_cluster_pmu_write_reg(SCM_AUX_CPCT_N_CONFIG + number, &cfg);
		}
	}
}

static void arc_cluster_pmu_event_configure(struct perf_event *event)
{
	struct hw_perf_event *hw = &event->hw;
	int number;
	u32 vv;

	if (WARN_ON_ONCE(hw->idx < 0))
		return;

	vv = 0;
	number = hw->idx * 8;
	arc_cluster_pmu_write_reg(SCM_AUX_CPCT_COUNTL + number, &vv);
	arc_cluster_pmu_write_reg(SCM_AUX_CPCT_COUNTH + number, &vv);
	local64_set(&hw->prev_count, 0);
}

static int arc_cluster_pmu_event_set_period(struct perf_event *event)
{
	struct hw_perf_event *hw = &event->hw;
	s64 left = local64_read(&hw->period_left);
	s64 period = hw->sample_period;
	int idx = hw->idx;
	int overflow = 0;
	s64 value;
	u32 vv;
	int number;

	if (unlikely(left <= -period)) {
		/* left underflowed by more than period */
		left = period;
		local64_set(&hw->period_left, left);
		hw->last_period = period;
		overflow = 1;
	} else if (unlikely(left <= 0)) {
		/* left underflowed by less than period */
		left += period;
		local64_set(&hw->period_left, left);
		hw->last_period = period;
		overflow = 1;
	}

	if (left > arc_cluster_pmu->max_period)
		left = arc_cluster_pmu->max_period;

	value = arc_cluster_pmu->max_period - left;
	local64_set(&hw->prev_count, value);

	/* select counter, 0..31 */
	number = 8 * idx;

	/* write value */
	vv = (u32)value;
	arc_cluster_pmu_write_reg(SCM_AUX_CPCT_COUNTL + number, &vv);
	vv = (u32)(value >> 32ULL);
	arc_cluster_pmu_write_reg(SCM_AUX_CPCT_COUNTH + number, &vv);

	perf_event_update_userpage(event);

	return overflow;
}

/*
 * Assigns hardware counter to hardware condition.
 * Note that there is no separate start/stop mechanism;
 * stopping is achieved by assigning the 'never' condition
 */
static void arc_cluster_pmu_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;
	int number = 8 * idx;
	u32 vv;

	if (WARN_ON_ONCE(idx < 0))
		return;

	if (WARN_ON_ONCE(!(hwc->state & PERF_HES_STOPPED)))
		return;

	if (flags & PERF_EF_RELOAD) {
		WARN_ON_ONCE(!(hwc->state & PERF_HES_UPTODATE));
		arc_cluster_pmu_event_configure(event);
	}

	hwc->state = 0;

	arc_cluster_pmu_event_set_period(event);

	/* enable interrupt for this counter */
	if (is_sampling_event(event)) {
		arc_cluster_pmu_read_reg(SCM_AUX_CPCT_INT_CTRL, &vv);
		vv |= BIT(idx);
		arc_cluster_pmu_write_reg(SCM_AUX_CPCT_INT_CTRL, &vv);
	}

	/* enable ARC cluster pmu here */
	arc_cluster_pmu_write_reg(SCM_AUX_CPCT_N_CONFIG + number, &hwc->config);

	perf_event_update_userpage(event);
}

static void arc_cluster_pmu_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;
	u32 vv;
	int number;
	struct cpct_n_config cfg;

	if (event->hw.state & PERF_HES_STOPPED)
		return;

	if (WARN_ON_ONCE(idx < 0))
		return;

	/* disable interrupt for this counter */
	if (is_sampling_event(event)) {
		/*
		 * Reset interrupt flag by writing of 1. This is required
		 * to make sure pending interrupt was not left.
		 * This also clears enable bit for the SCM_AUX_CPCT_INT_CTRL.
		 */
		vv = BIT(idx);
		arc_cluster_pmu_write_reg(SCM_AUX_CPCT_INT_ACT, &vv);
	}

	number = idx * 8;
	arc_cluster_pmu_read_reg(SCM_AUX_CPCT_N_CONFIG + number, &cfg);
	cfg.lce = 1;
	cfg.len = 0;
	arc_cluster_pmu_write_reg(SCM_AUX_CPCT_N_CONFIG + number, &cfg);

	event->hw.state |= PERF_HES_STOPPED;

	if ((flags & PERF_EF_UPDATE) &&
	    !(event->hw.state & PERF_HES_UPTODATE)) {
		arc_cluster_perf_event_update(event, &event->hw, idx);
		event->hw.state |= PERF_HES_UPTODATE;
	}
}

static int arc_cluster_pmu_find_free_idx(struct perf_event *event)
{
	int ii;
	struct hw_perf_event *hw;
	struct arc_cluster_cpu *pcpu = this_cpu_ptr(arc_cluster_pmu->pcpu);

	for (ii = 0; ii < ARC_CLUSTER_PERF_MAX_COUNTERS; ii++) {
		if (pcpu->events[ii] == NULL) {
			pcpu->events[ii] = event;
			hw = &event->hw;
			hw->idx = ii;
			return ii;
		}
	}
	return -1;
}

/* allocate hardware counter and optionally start counting */
static int arc_cluster_pmu_add(struct perf_event *event, int flags)
{
	struct hw_perf_event *hw = &event->hw;
	int idx;
	int number;
	u32 vv;

	idx = arc_cluster_pmu_find_free_idx(event);
	if (WARN_ON_ONCE(idx < 0))
		return -EAGAIN;

	number = idx * 8;

	if (is_sampling_event(event)) {
		/* mimic full counter overflow as other arches do */
		vv = (u32)arc_cluster_pmu->max_period;
		arc_cluster_pmu_write_reg(SCM_AUX_CPCT_INT_CNTL + number, &vv);
		vv = (u32)(arc_cluster_pmu->max_period >> 32ULL);
		arc_cluster_pmu_write_reg(SCM_AUX_CPCT_INT_CNTH + number, &vv);
	}

	vv = 0;
	arc_cluster_pmu_write_reg(SCM_AUX_CPCT_N_CONFIG + number, &vv);
	arc_cluster_pmu_event_configure(event);

	hw->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;
	if (flags & PERF_EF_START)
		arc_cluster_pmu_start(event, PERF_EF_RELOAD);

	/* propagate changes to the userspace mapping */
	perf_event_update_userpage(event);

	return 0;
}

static void arc_cluster_pmu_del(struct perf_event *event, int flags)
{
	struct hw_perf_event *hw = &event->hw;
	int ii;
	struct arc_cluster_cpu *pcpu = this_cpu_ptr(arc_cluster_pmu->pcpu);
	struct cpct_n_config cfg;

	if (WARN_ON_ONCE(hw->idx < 0))
		return;

	arc_cluster_pmu_stop(event, PERF_EF_UPDATE);

	cfg.val = 0;
	cfg.cc_num = 0xFFFF;
	cfg.lce = 1;
	arc_cluster_pmu_write_reg(SCM_AUX_CPCT_N_CONFIG + hw->idx * 8, &cfg);

	for (ii = 0; ii < ARC_CLUSTER_PERF_MAX_COUNTERS; ii++) {
		if (pcpu->events[ii] == event) {
			pcpu->events[ii] = NULL;
			break;
		}
	}

	if (WARN_ON_ONCE(ii == ARC_CLUSTER_PERF_MAX_COUNTERS))
		return;

	hw->idx = -1;

	/* propagate changes to the userspace mapping */
	perf_event_update_userpage(event);
}

static irqreturn_t arc_cluster_pmu_intr(int irq, void *dev)
{
	struct perf_sample_data data;
	struct pt_regs *regs;
	u32 active_ints, vv;
	int idx;
	struct arc_cluster_cpu *pcpu = this_cpu_ptr(arc_cluster_pmu->pcpu);

	arc_cluster_pmu_read_reg(SCM_AUX_CPCT_INT_ACT, &active_ints);
	if (!active_ints) {
		return IRQ_HANDLED;
	}

	arc_cluster_pmu_disable(&arc_cluster_pmu->pmu);

	do {
		struct perf_event *event;
		struct hw_perf_event *hw;

		idx = __ffs(active_ints);

		event = pcpu->events[idx];
		if (WARN_ON_ONCE(event == NULL)) {
			arc_cluster_pmu_enable(&arc_cluster_pmu->pmu);
			return IRQ_HANDLED;
		}

		hw = &event->hw;

		/* reset interrupt flag by writing of 1 */
		vv = BIT(idx);
		arc_cluster_pmu_write_reg(SCM_AUX_CPCT_INT_ACT, &vv);

		/*
		 * On reset of "interrupt active" bit corresponding
		 * "interrupt enable" bit gets automatically reset as well.
		 * Now we need to re-enable interrupt for the counter.
		 */
		arc_cluster_pmu_read_reg(SCM_AUX_CPCT_INT_CTRL, &vv);
		vv |= BIT(idx);
		arc_cluster_pmu_write_reg(SCM_AUX_CPCT_INT_CTRL, &vv);

		WARN_ON_ONCE(hw->idx != idx);

		arc_cluster_perf_event_update(event, &event->hw, event->hw.idx);
		perf_sample_data_init(&data, 0, hw->last_period);
		if (arc_cluster_pmu_event_set_period(event)) {
			regs = get_irq_regs();
			if (perf_event_overflow(event, &data, regs))
				arc_cluster_pmu_stop(event, 0);
		}

		active_ints &= ~BIT(idx);
	} while (active_ints);

	arc_cluster_pmu_enable(&arc_cluster_pmu->pmu);
	return IRQ_HANDLED;
}

static void arc_cluster_cpu_pmu_irq_init(void *data)
{
	int irq = *(int *)data;
	u32 vv;

	if (cpumask_first(&pmu_cpu) != smp_processor_id())
		return;

	enable_percpu_irq(irq, IRQ_TYPE_NONE);

	/* clear all pending interrupt flags */
	vv = 0xffffffff;
	arc_cluster_pmu_write_reg(SCM_AUX_CPCT_INT_ACT, &vv);
}

/* initializes hw_perf_event structure if event is supported */
static int arc_cluster_pmu_event_init(struct perf_event *event)
{
	struct hw_perf_event *hw = &event->hw;
	struct cpct_n_config cfg;

	if (event->attr.type != arc_cluster_pmu->pmu.type)
		return -ENOENT;

	/* per-task mode not supported */
	if (WARN_ON_ONCE(event->cpu < 0))
		return -EOPNOTSUPP;

	/* don't allow groups with mixed PMUs, except for s/w events */
	if (event->group_leader->pmu != event->pmu && !is_software_event(event->group_leader)) {
		return -EINVAL;
	}

	if (!is_sampling_event(event)) {
		hw->sample_period = arc_cluster_pmu->max_period;
		hw->last_period = hw->sample_period;
		local64_set(&hw->period_left, hw->sample_period);
	}

	if (event->attr.config >= arc_cluster_pmu->n_events) {
		return -ENOENT;
	}

	cfg.val = 0;
	cfg.cc_num = arc_cluster_pmu->raw_entry[event->attr.config].cc_number;
	cfg.lce = 1;
	hw->config = cfg.val;
	hw->idx = -1;

	return 0;
}

static int arc_cluster_pmu_raw_alloc(struct device *dev)
{
	attr = devm_kmalloc_array(dev, arc_cluster_pmu->n_events + 1,
		sizeof(*attr), GFP_KERNEL | __GFP_ZERO);
	if (!attr)
		return -ENOMEM;

	event_attrs = devm_kmalloc_array(dev, arc_cluster_pmu->n_events + 1,
		sizeof(*event_attrs), GFP_KERNEL | __GFP_ZERO);
	if (!event_attrs) {
		devm_kfree(dev, attr);
		return -ENOMEM;
	}

	arc_cluster_pmu->raw_entry = devm_kmalloc_array(dev, arc_cluster_pmu->n_events,
		sizeof(*arc_cluster_pmu->raw_entry), GFP_KERNEL | __GFP_ZERO);
	if (!arc_cluster_pmu->raw_entry) {
		devm_kfree(dev, attr);
		devm_kfree(dev, event_attrs);
		return -ENOMEM;
	}

	return 0;
}

static void arc_cluster_pmu_raw_free(struct device *dev)
{
	devm_kfree(dev, attr);
	devm_kfree(dev, event_attrs);
	devm_kfree(dev, arc_cluster_pmu->raw_entry);
}

static int arc_cluster_pmu_is_present(void)
{
    struct cpct_build bld;
    arc_cluster_pmu_read_reg(SCM_AUX_CPCT_BUILD, &bld);
    return bld.ver;
}

static int arc_cluster_pmu_get_n_counters(void)
{
    struct cpct_build bld;
    arc_cluster_pmu_read_reg(SCM_AUX_CPCT_BUILD, &bld);
    return bld.num_ctrs;
}

static int arc_cluster_pmu_has_interrupt(void)
{
    struct cpct_build bld;
    arc_cluster_pmu_read_reg(SCM_AUX_CPCT_BUILD, &bld);
    return bld.i;
}

static int arc_cluster_pmu_get_cnt_bits(void)
{
    struct cpct_build bld;
    arc_cluster_pmu_read_reg(SCM_AUX_CPCT_BUILD, &bld);
    return 32 + 16 * bld.cs;
}

static int arc_cluster_pmu_get_events_number(void)
{
    int ii;
    struct cpct_cc_num cc_num;
    union cpct_cc_name name;
    int n_actual_conditions = 0;

    name.cc[CPCT_NAME_SZ-1] = 0;
    for (ii = 0; ii < MAX_CONDITIONS_NUMBER; ii++ ) {
        cc_num.cc_num = ii;
        cc_num.res = 0; /* recomended to write with 0 */
        arc_cluster_pmu_write_reg(SCM_AUX_CPCT_CC_NUM, &cc_num);
        arc_cluster_pmu_read_reg(SCM_AUX_CPCT_CC_NAME0, &name.uu[0]);
        arc_cluster_pmu_read_reg(SCM_AUX_CPCT_CC_NAME1, &name.uu[1]);
        arc_cluster_pmu_read_reg(SCM_AUX_CPCT_CC_NAME2, &name.uu[2]);
        arc_cluster_pmu_read_reg(SCM_AUX_CPCT_CC_NAME3, &name.uu[3]);
        if (strlen(name.cc) == 0) {
            continue;
        }
        n_actual_conditions++;
    }
    return n_actual_conditions;
}

static int arc_cluster_pmu_fill_events(void)
{
    int ii;
    struct cpct_cc_num cc_num;
    union cpct_cc_name name;
    int n_actual_conditions = 0;

    name.cc[CPCT_NAME_SZ-1] = 0;
    for (ii = 0; ii < MAX_CONDITIONS_NUMBER; ii++ ) {
        cc_num.cc_num = ii;
        cc_num.res = 0; /* recomended to write with 0 */
        arc_cluster_pmu_write_reg(SCM_AUX_CPCT_CC_NUM, &cc_num);
        arc_cluster_pmu_read_reg(SCM_AUX_CPCT_CC_NAME0, &name.uu[0]);
        arc_cluster_pmu_read_reg(SCM_AUX_CPCT_CC_NAME1, &name.uu[1]);
        arc_cluster_pmu_read_reg(SCM_AUX_CPCT_CC_NAME2, &name.uu[2]);
        arc_cluster_pmu_read_reg(SCM_AUX_CPCT_CC_NAME3, &name.uu[3]);
        if (strlen(name.cc) == 0) {
            continue;
        }

		arc_cluster_pmu->raw_entry[n_actual_conditions].cc_number = ii;
        strcpy(arc_cluster_pmu->raw_entry[n_actual_conditions].name.cc, name.cc);

        n_actual_conditions++;
		if (n_actual_conditions >= arc_cluster_pmu->n_events) {
			break;
		}
    }

    return n_actual_conditions;
}

//------------------------------------------------------------
/*
 * We don't add attrs here as we don't have pre-defined list of cluster events.
 * We will generate and add attrs dynamically in probe() after we read HW
 * configuration.
 */
static struct attribute_group arc_cluster_events_attr_gr = {
	.name = "events",
};
//------------------------------------------------------------
static ssize_t arc_pmu_events_sysfs_show(struct device *dev,
					 struct device_attribute *attr,
					 char *page)
{
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr);
	return sprintf(page, "event=0x%04llx\n", pmu_attr->id);
}

static void arc_cluster_pmu_add_raw_event_attr(int j)
{
	attr[j].attr.attr.name = arc_cluster_pmu->raw_entry[j].name.cc;
	attr[j].attr.attr.mode = VERIFY_OCTAL_PERMISSIONS(0444);
	attr[j].attr.show = arc_pmu_events_sysfs_show;
	attr[j].id = j;
	event_attrs[j] = &(attr[j].attr.attr);
}
//------------------------------------------------------------
/* event field occupies the bottom 16 bits of our config field */
PMU_FORMAT_ATTR(event, "config:0-15");
static struct attribute *arc_cluster_pmu_format_attrs[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group arc_cluster_format_attr_gr = {
	.name = "format",
	.attrs = arc_cluster_pmu_format_attrs,
};
//------------------------------------------------------------
static ssize_t arc_cluster_cpumask_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	return cpumap_print_to_pagebuf(true, buf, &pmu_cpu);
}

static DEVICE_ATTR(cpumask, S_IRUGO, arc_cluster_cpumask_show, NULL);

static struct attribute *arc_cluster_cpumask_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

/* perf userspace reads this attribute to determine which cpus to open counters on */
static struct attribute_group arc_cluster_cpumask_attr_group = {
	.attrs = arc_cluster_cpumask_attrs,
};
//------------------------------------------------------------
static const struct attribute_group *arc_cluster_attr_groups[] = {
	&arc_cluster_format_attr_gr,
	&arc_cluster_cpumask_attr_group,
	&arc_cluster_events_attr_gr,
	NULL,
};
//------------------------------------------------------------
static int arc_cluster_pmu_online_cpu(unsigned int cpu)
{
	/* select the first online CPU as the designated reader */
	if (cpumask_empty(&pmu_cpu)) {
		cpumask_set_cpu(cpu, &pmu_cpu);
	}
	return 0;
}

static int arc_cluster_pmu_offline_cpu(unsigned int cpu)
{
	unsigned int target;

	if (!cpumask_test_and_clear_cpu(cpu, &pmu_cpu))
		return 0;

	if (arc_cluster_pmu->irq >= 0)
		disable_percpu_irq(arc_cluster_pmu->irq);

	target = cpumask_any_but(cpu_online_mask, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	perf_pmu_migrate_context(&arc_cluster_pmu->pmu, cpu, target);
	cpumask_set_cpu(target, &pmu_cpu);
	on_each_cpu(arc_cluster_cpu_pmu_irq_init, &arc_cluster_pmu->irq, 1);

	return 0;
}

//------------------------------------------------------------
static int arc_cluster_pmu_device_probe(struct platform_device *pdev)
{
	int ii;
	int has_interrupts = 0, irq = -1;
	int counter_size;	/* in bits */
	int ncounters;
	int nevents;
	u32 int_reg;
	struct bcr_clustv3_cfg cbcr;
	struct arc_cluster_cpu __percpu *pcpu;
	int ret;

#ifndef CONFIG_ISA_ARCV3
	pr_err("Cluster PMU driver must be used only on ARCv3 platform!\n");
	return -ENODEV;
#endif

	READ_BCR(ARC_REG_CLUSTER_BCR, cbcr);
	if (!cbcr.ver_maj || !arc_cluster_pmu_is_present()){
		pr_err("Cluster PCT module doesn't present in the system.\n");
		return -ENODEV;
	}

	ncounters = arc_cluster_pmu_get_n_counters();
	if (!ncounters) {
		pr_err("Cluster PCT module doesn't have counters.\n");
		return -EINVAL;
	}

	nevents = arc_cluster_pmu_get_events_number();
	if (!nevents) {
		pr_err("Cluster PCT module doesn't have countable conditions.\n");
		return -EINVAL;
	}

	arc_cluster_pmu = devm_kzalloc(&pdev->dev, sizeof(struct arc_cluster_pmu), GFP_KERNEL);
	if (!arc_cluster_pmu)
		return -ENOMEM;

	arc_cluster_pmu->n_counters = ncounters;
	arc_cluster_pmu->n_events = nevents;
	counter_size = arc_cluster_pmu_get_cnt_bits();
	arc_cluster_pmu->max_period = (1ULL << counter_size) / 2 - 1ULL;
	has_interrupts = arc_cluster_pmu_has_interrupt();

	pr_info("ARCv3 cluster perf\t: %d counters (%d bits), %d conditions%s\n",
		arc_cluster_pmu->n_counters, counter_size, arc_cluster_pmu->n_events,
		has_interrupts ? ", [overflow IRQ support]" : "");

	if (arc_cluster_pmu_raw_alloc(&pdev->dev)) {
		devm_kfree(&pdev->dev, arc_cluster_pmu);
		return -ENOMEM;
	}

	if (arc_cluster_pmu_fill_events() == 0 ) {
		pr_err("Error! While preparing events structure.\n");
		arc_cluster_pmu_raw_free(&pdev->dev);
		return -EINVAL;
	}

	pcpu = devm_alloc_percpu(&pdev->dev, struct arc_cluster_cpu);
	if (!pcpu) {
		return -ENOMEM;
	}
	arc_cluster_pmu->pcpu = pcpu;

	/* loop through all available h/w condition indexes */
	for (ii = 0; ii < nevents; ii++) {
		arc_cluster_pmu_add_raw_event_attr(ii);
	}

	arc_cluster_events_attr_gr.attrs = event_attrs;

	arc_cluster_pmu->pmu = (struct pmu) {
		.pmu_enable	= arc_cluster_pmu_enable,
		.pmu_disable	= arc_cluster_pmu_disable,
		.event_init	= arc_cluster_pmu_event_init,
		.add		= arc_cluster_pmu_add,
		.del		= arc_cluster_pmu_del,
		.start		= arc_cluster_pmu_start,
		.stop		= arc_cluster_pmu_stop,
		.read		= arc_cluster_pmu_read,
		.attr_groups = arc_cluster_attr_groups,
		.capabilities = PERF_PMU_CAP_NO_EXCLUDE,
		.task_ctx_nr = perf_invalid_context,
	};

	/* clear cpumask attributes. We will set it in arc_cluster_pmu_online_cpu */
	cpumask_clear(&pmu_cpu);

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
					"perf/arc/cluster:online",
					arc_cluster_pmu_online_cpu, arc_cluster_pmu_offline_cpu);
	if (ret < 0)
		return -EINVAL;

	if (has_interrupts) {
		irq = platform_get_irq(pdev, 0);
		if (irq >= 0) {
			int ret;

			arc_cluster_pmu->irq = irq;

			/* intc map function ensures irq_set_percpu_devid() called */
			ret = request_percpu_irq(irq, arc_cluster_pmu_intr, "ARC cluster perf counters",
						 arc_cluster_pmu->pcpu);

			if (!ret) {
				on_each_cpu(arc_cluster_cpu_pmu_irq_init, &irq, 1);
			} else {
				arc_cluster_pmu->irq = irq = -1;
			}
		} else {
			arc_cluster_pmu->irq = -1;
		}
		int_reg = 0;
		arc_cluster_pmu_write_reg(SCM_AUX_CPCT_INT_CTRL, &int_reg);
	}

	if (irq == -1)
		arc_cluster_pmu->pmu.capabilities |= PERF_PMU_CAP_NO_INTERRUPT;

	/*
	 * perf parser doesn't really like '-' symbol in events name, so let's
	 * use '_' in arc pct name as it goes to kernel PMU event prefix.
	 */
	ret = perf_pmu_register(&arc_cluster_pmu->pmu, "arc_cluster_pct", -1);
	if(ret)
		arc_cluster_pmu->pcpu = NULL;

	return ret;
}

static const struct of_device_id arc_cluster_pmu_match[] = {
	{ .compatible = "snps,arcv3-cluster-pmu" },
	{},
};
MODULE_DEVICE_TABLE(of, arc_cluster_pmu_match);

static struct platform_driver arc_cluster_pmu_driver = {
	.driver	= {
		.name		= "ARCv3-cluster-PMU",
		.of_match_table = of_match_ptr(arc_cluster_pmu_match),
	},
	.probe		= arc_cluster_pmu_device_probe,
};

module_platform_driver(arc_cluster_pmu_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bolsh@synopsys.com");
MODULE_DESCRIPTION("ARCv3 cluster PMU driver");
