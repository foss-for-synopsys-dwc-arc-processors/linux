// SPDX-License-Identifier: GPL-2.0+
//
// Linux L2$ performance counter support for ARCv2 CPUs.
//
// Copyright (C) 2013-2022 Synopsys, Inc. (www.synopsys.com)

#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/perf_event.h>
#include <linux/platform_device.h>
#include <asm/arcregs.h>
#include <asm/stacktrace.h>
#include <asm/perf_slc.h>


enum arc_pmu_attr_groups {
	ARCPMU_ATTR_GR_EVENTS,
	ARCPMU_ATTR_GR_FORMATS,
	ARCPMU_ATTR_GR_CPUMASK,
	ARCPMU_NR_ATTR_GR
};

struct arc_pmu_slc_raw_event_entry {
	char name[ARCPMU_EVENT_NAME_LEN];
};

struct arc_pmu_slc {
	struct pmu	pmu;
	int		n_counters;
	int		n_events;
    u64		max_period;

	struct arc_pmu_slc_raw_event_entry	*raw_entry;
	struct attribute		**attrs;
	struct perf_pmu_events_attr	*attr;
	const struct attribute_group	*attr_groups[ARCPMU_NR_ATTR_GR + 1];
};

struct arc_pmu_slc_cpu {
	/*
	 * A 1 bit for an index indicates that the counter is being used for
	 * an event. A 0 means that the counter can be used.
	 */
	unsigned long used_mask[BITS_TO_LONGS(ARC_PERF_MAX_COUNTERS)];
	/*
	 * The events that are active on the PMU for the given index.
	 */
	struct perf_event *act_counter[ARC_PERF_MAX_COUNTERS];
};

static cpumask_t pmu_cpu_online;
static struct arc_pmu_slc *arc_slc_pmu;
static DEFINE_PER_CPU(struct arc_pmu_slc_cpu, arc_pmu_cpu);

/* event field occupies the bottom 15 bits of our config field */
PMU_FORMAT_ATTR(event, "config:0-7");
static struct attribute *arc_pmu_slc_format_attrs[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group arc_pmu_slc_format_attr_gr = {
	.name = "format",
	.attrs = arc_pmu_slc_format_attrs,
};

static ssize_t arc_pmu_slc_events_sysfs_show(struct device *dev,
					 struct device_attribute *attr,
					 char *page)
{
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr);
	return sprintf(page, "event=0x%04llx\n", pmu_attr->id);
}

/*
 * We don't add attrs here as we don't have pre-defined list of perf events.
 * We will generate and add attrs dynamically in probe() after we read HW
 * configuration.
 */
static struct attribute_group arc_pmu_slc_events_attr_gr = {
	.name = "events",
};

static void arc_pmu_slc_add_raw_event_attr(int j, char *str)
{
    arc_slc_pmu->raw_entry[j].name[ARCPMU_EVENT_NAME_LEN - 1] = 0;
	memmove(arc_slc_pmu->raw_entry[j].name, str, ARCPMU_EVENT_NAME_LEN - 1);
	arc_slc_pmu->attr[j].attr.attr.name = arc_slc_pmu->raw_entry[j].name;
	arc_slc_pmu->attr[j].attr.attr.mode = VERIFY_OCTAL_PERMISSIONS(0444);
	arc_slc_pmu->attr[j].attr.show = arc_pmu_slc_events_sysfs_show;
	arc_slc_pmu->attr[j].id = j;
	arc_slc_pmu->attrs[j] = &(arc_slc_pmu->attr[j].attr.attr);
}

static int arc_pmu_slc_raw_alloc(struct device *dev, int n_events)
{
	arc_slc_pmu->attr = devm_kmalloc_array(dev, n_events + 1,
		sizeof(*arc_slc_pmu->attr), GFP_KERNEL | __GFP_ZERO);
	if (!arc_slc_pmu->attr)
		return -ENOMEM;

	arc_slc_pmu->attrs = devm_kmalloc_array(dev, n_events + 1,
		sizeof(*arc_slc_pmu->attrs), GFP_KERNEL | __GFP_ZERO);
	if (!arc_slc_pmu->attrs) {
        devm_kfree(dev, arc_slc_pmu->attr);
		return -ENOMEM;
    }

	arc_slc_pmu->raw_entry = devm_kmalloc_array(dev, n_events,
		sizeof(*arc_slc_pmu->raw_entry), GFP_KERNEL | __GFP_ZERO);
	if (!arc_slc_pmu->raw_entry) {
        devm_kfree(dev, arc_slc_pmu->attr);
        devm_kfree(dev, arc_slc_pmu->attrs);
		return -ENOMEM;
    }

	return 0;
}

static void arc_pmu_slc_pcts_init(int n_counters)
{
	int ii;
	struct slc_aux_pm_cmd pm_cmd;

	for (ii=0; ii < n_counters; ii++) {
        pm_cmd.cmd = SLC_AUX_PM_CMD_ENABLE;
        pm_cmd.cnum = ii;
        pm_cmd.evt = CONDITION_NONE_NUMBER;
        WRITE_AUX(SLC_AUX_PM_CMD, pm_cmd);
	}
	pm_cmd.cmd = SLC_AUX_PM_CMD_DISABLE_ALL;
    WRITE_AUX(SLC_AUX_PM_CMD, pm_cmd);
}

/* starts all counters, global enable. Optional. Fully enable this PMU  */
static void arc_pmu_slc_enable(struct pmu *pmu)
{
    struct slc_aux_pm_cmd pm_cmd;
    struct slc_aux_pm_event pm_event;
    int ii;

    for (ii=0; ii < SLC_AUX_CACHE_PCT_NUMMBER; ii++) {
        /* read the specified counter ii into the SLC_AUX_PM_EVENT reg */
        pm_cmd.cmd = SLC_AUX_PM_CMD_READ;
        pm_cmd.cnum = ii;
        WRITE_AUX(SLC_AUX_PM_CMD, pm_cmd);
        READ_BCR(SLC_AUX_PM_EVENT, pm_event);
		/* according to PRM needs to read the register twice */
        READ_BCR(SLC_AUX_PM_EVENT, pm_event);
		if(pm_event.evt == CONDITION_NONE_NUMBER)
			continue;
        /* now run counter ii again */
        pm_cmd.cmd = SLC_AUX_PM_CMD_ENABLE;
        pm_cmd.cnum = ii;
        pm_cmd.evt = pm_event.evt;
        WRITE_AUX(SLC_AUX_PM_CMD, pm_cmd);
    }
}

/* stops all counters. Optional. Fully disable this PMU */
static void arc_pmu_slc_disable(struct pmu *pmu)
{
    struct slc_aux_pm_cmd pm_cmd;
    pm_cmd.cmd = SLC_AUX_PM_CMD_DISABLE_ALL;
    WRITE_AUX(SLC_AUX_PM_CMD, pm_cmd);
}

/*
 * Assigns hardware counter to hardware condition.
 * Note that there is no separate start/stop mechanism;
 * stopping is achieved by assigning the 'never' condition
 */
static void arc_pmu_slc_start(struct perf_event *event, int flags)
{
    struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;
    struct slc_aux_pm_cmd pm_cmd;

	if (WARN_ON_ONCE(idx < 0))
		return;

	if (flags & PERF_EF_RELOAD)
		WARN_ON_ONCE(!(hwc->state & PERF_HES_UPTODATE));

	hwc->state = 0;

    /* assign counter=idx to count condition hwc->config */
    pm_cmd.cmd = SLC_AUX_PM_CMD_ENABLE;
    pm_cmd.cnum = idx;
    pm_cmd.evt = hwc->config;
    WRITE_AUX(SLC_AUX_PM_CMD, pm_cmd);
    /* clear just assigned counter. RTL doesn't clear the assigned counter 
		when SLC_AUX_PM_CMD_ENABLE is issued */
    pm_cmd.cmd = SLC_AUX_PM_CMD_READ_CLEAR;
    WRITE_AUX(SLC_AUX_PM_CMD, pm_cmd);
}

static void arc_pmu_slc_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;
    struct slc_aux_pm_cmd pm_cmd;

	if (!(event->hw.state & PERF_HES_STOPPED)) {
        pm_cmd.cmd = SLC_AUX_PM_CMD_ENABLE;
        pm_cmd.cnum = idx;
        pm_cmd.evt = CONDITION_NONE_NUMBER;
        WRITE_AUX(SLC_AUX_PM_CMD, pm_cmd);

		event->hw.state |= PERF_HES_STOPPED;
	}

	if ((flags & PERF_EF_UPDATE) &&
	    !(event->hw.state & PERF_HES_UPTODATE)) {
		arc_perf_event_update(event, &event->hw, idx);
		event->hw.state |= PERF_HES_UPTODATE;
	}
}

/* allocate hardware counter and optionally start counting */
static int arc_pmu_slc_add(struct perf_event *event, int flags)
{
	struct arc_pmu_slc_cpu *pmu_cpu = this_cpu_ptr(&arc_pmu_cpu);
	struct hw_perf_event *hwc = &event->hw;
	int idx;
    struct slc_aux_pm_cmd pm_cmd;

	idx = ffz(pmu_cpu->used_mask[0]);
	if (idx >= arc_slc_pmu->n_counters)
		return -EAGAIN;

	__set_bit(idx, pmu_cpu->used_mask);
	hwc->idx = idx;

	pmu_cpu->act_counter[idx] = event;

    /* clear just assigned counter */
    pm_cmd.cmd = SLC_AUX_PM_CMD_READ_CLEAR;
    pm_cmd.cnum = idx;
    pm_cmd.evt = CONDITION_NONE_NUMBER;
    WRITE_AUX(SLC_AUX_PM_CMD, pm_cmd);

	local64_set(&hwc->prev_count, 0);

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;
	if (flags & PERF_EF_START)
		arc_pmu_slc_start(event, PERF_EF_RELOAD);

	perf_event_update_userpage(event);
	return 0;
}

static void arc_pmu_slc_del(struct perf_event *event, int flags)
{
    struct arc_pmu_slc_cpu *pmu_cpu = this_cpu_ptr(&arc_pmu_cpu);

	arc_pmu_slc_stop(event, PERF_EF_UPDATE);
	__clear_bit(event->hw.idx, pmu_cpu->used_mask);

	pmu_cpu->act_counter[event->hw.idx] = NULL;
	event->hw.idx = -1;

	perf_event_update_userpage(event);
}

/* read counter #idx; note that counter# != event# on ARC! */
static u64 arc_pmu_slc_read_counter(int idx)
{
    struct slc_aux_pm_cmd pm_cmd;
    struct slc_aux_pm_cnt cnt0, cnt1;
    u64 result;

    pm_cmd.cmd = SLC_AUX_PM_CMD_READ; /* read the specified counter and event */
    pm_cmd.cnum = idx; /* counter number */
    WRITE_AUX(SLC_AUX_PM_CMD, pm_cmd);

    READ_BCR(SLC_AUX_PM_CNT1, cnt1);
    READ_BCR(SLC_AUX_PM_CNT0, cnt0);
	/* according to PRM needs to read registers twice */
    READ_BCR(SLC_AUX_PM_CNT1, cnt1);
    READ_BCR(SLC_AUX_PM_CNT0, cnt0);

    result = ((u64)cnt1.cnt << 32ULL) | (u64)cnt0.cnt;
	return result;
}

static void arc_perf_event_update(struct perf_event *event,
				  struct hw_perf_event *hwc, int idx)
{
	u64 prev_raw_count = local64_read(&hwc->prev_count);
	u64 new_raw_count = arc_pmu_slc_read_counter(idx);
	s64 delta = new_raw_count - prev_raw_count;

	/*
	 * We aren't afraid of hwc->prev_count changing beneath our feet
	 * because there's no way for us to re-enter this function anytime.
	 */
	local64_set(&hwc->prev_count, new_raw_count);
	local64_add(delta, &event->count);
	local64_sub(delta, &hwc->period_left);
}

static void arc_pmu_slc_read(struct perf_event *event)
{
    arc_perf_event_update(event, &event->hw, event->hw.idx);
}

/* initializes hw_perf_event structure if event is supported */
static int arc_pmu_slc_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	if (event->attr.type != arc_slc_pmu->pmu.type)
		return -ENOENT;

	/* per-task mode not supported */
	if (WARN_ON_ONCE(event->cpu < 0))
		return -EOPNOTSUPP;

	/* don't allow groups with mixed PMUs, except for s/w events */
	if (event->group_leader->pmu != event->pmu && !is_software_event(event->group_leader)) {
		return -EINVAL;
	}

	if (!is_sampling_event(event)) {
		hwc->sample_period = arc_slc_pmu->max_period;
		hwc->last_period = hwc->sample_period;
		local64_set(&hwc->period_left, hwc->sample_period);
	}

	if (event->attr.config >= arc_slc_pmu->n_events) {
		return -ENOENT;
	}

	hwc->config = event->attr.config;

	pr_debug("init slc_pmu event with idx %lld . type=%d \'%s\'\n",
		 event->attr.config,
		 event->attr.type,
		 arc_slc_pmu->raw_entry[event->attr.config].name);

	return 0;
}

static ssize_t arc_pmu_slc_cpumask_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	return cpumap_print_to_pagebuf(true, buf, &pmu_cpu_online);
}

static DEVICE_ATTR(cpumask, S_IRUGO, arc_pmu_slc_cpumask_show, NULL);

static struct attribute *arc_pmu_cpumask_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

/* perf userspace reads this attribute to determine which cpus to open counters on */
static struct attribute_group arc_pmu_cpumask_attr_group = {
	.attrs = arc_pmu_cpumask_attrs,
};

static int arc_pmu_slc_online_cpu(unsigned int cpu)
{
	/* select the first online CPU as the designated reader */
	if (cpumask_empty(&pmu_cpu_online)) {
		cpumask_set_cpu(cpu, &pmu_cpu_online);
	}
	return 0;
}

static int arc_pmu_slc_offline_cpu(unsigned int cpu)
{
	unsigned int target;

	if (!cpumask_test_and_clear_cpu(cpu, &pmu_cpu_online))
		return 0;

	target = cpumask_any_but(cpu_online_mask, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	perf_pmu_migrate_context(&arc_slc_pmu->pmu, cpu, target);
	cpumask_set_cpu(target, &pmu_cpu_online);

	return 0;
}

static int arc_pmu_slc_device_probe(struct platform_device *pdev)
{
    int i;
    struct csm_build csm_br;
    struct slc_build scl_br;
    struct slc_aux_cache_config cache_cfg;
    int counter_size;	/* in bits */
	int ret;

#ifndef CONFIG_ISA_ARCV2
	pr_err("PMU SLC driver must be used only on ARCv2 platform!\n");
	return -ENODEV;
#endif

    BUILD_BUG_ON(SLC_AUX_CACHE_PCT_NUMMBER > 32);

    READ_BCR(CSM_BUILD, csm_br);
	if (!csm_br.ver) {
		pr_err("This system does not have the cluster shared memory!\n");
		return -ENODEV;
	}

    READ_BCR(SLC_BUILD, scl_br);
	if (!scl_br.ver) {
		pr_err("This system does not have L2$!\n");
		return -ENODEV;
	}

	arc_slc_pmu = devm_kzalloc(&pdev->dev, sizeof(struct arc_pmu_slc), GFP_KERNEL);
	if (!arc_slc_pmu)
		return -ENOMEM;

    READ_BCR(SLC_AUX_CACHE_CONFIG, cache_cfg);
    arc_slc_pmu->n_counters = cache_cfg.pm_num + 1;
    if (WARN_ON(arc_slc_pmu->n_counters > SLC_AUX_CACHE_PCT_NUMMBER)) {
        devm_kfree(&pdev->dev, arc_slc_pmu);
		return -EINVAL;
    }

    counter_size = 32 + (cache_cfg.pms << 4);
    arc_slc_pmu->n_events = ARCV2_SLC_NUM_OF_EVENTS;

    if (arc_pmu_slc_raw_alloc(&pdev->dev, arc_slc_pmu->n_events)) {
        devm_kfree(&pdev->dev, arc_slc_pmu);
		return -ENOMEM;
    }

    arc_slc_pmu->max_period = (1ULL << counter_size) / 2 - 1ULL;

    pr_info("ARCv2 SLC perf [v%d]\t: %d counters (%d bits), %d conditions\n",
		scl_br.ver, arc_slc_pmu->n_counters, counter_size, arc_slc_pmu->n_events);

	/* loop thru all available h/w condition indexes */
	for (i = 0; i < arc_slc_pmu->n_events; i++) {
		arc_pmu_slc_add_raw_event_attr(i, pct_names[i]);
	}

    arc_pmu_slc_events_attr_gr.attrs = arc_slc_pmu->attrs;
	arc_slc_pmu->attr_groups[ARCPMU_ATTR_GR_EVENTS] = &arc_pmu_slc_events_attr_gr;
	arc_slc_pmu->attr_groups[ARCPMU_ATTR_GR_FORMATS] = &arc_pmu_slc_format_attr_gr;
	arc_slc_pmu->attr_groups[ARCPMU_ATTR_GR_CPUMASK] = &arc_pmu_cpumask_attr_group;

	arc_slc_pmu->pmu = (struct pmu) {
        .event_init	    = arc_pmu_slc_event_init,
		.pmu_enable	    = arc_pmu_slc_enable,
		.pmu_disable	= arc_pmu_slc_disable,
		.add		    = arc_pmu_slc_add,
		.del		    = arc_pmu_slc_del,
		.start		    = arc_pmu_slc_start,
		.stop		    = arc_pmu_slc_stop,
		.read		    = arc_pmu_slc_read,
		.attr_groups	= arc_slc_pmu->attr_groups,
		.capabilities 	= PERF_PMU_CAP_NO_EXCLUDE | PERF_PMU_CAP_NO_INTERRUPT,
		.task_ctx_nr 	= perf_invalid_context,
	};

	/* clear cpumask attributes. We will set it in arc_cluster_pmu_online_cpu */
	cpumask_clear(&pmu_cpu_online);

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
					"perf/arc/slc_pmu:online",
					arc_pmu_slc_online_cpu, arc_pmu_slc_offline_cpu);
	if (ret < 0)
		return -EINVAL;

	/* set all counters as default */
	arc_pmu_slc_pcts_init(arc_slc_pmu->n_counters);

	/*
	 * perf parser doesn't really like '-' symbol in events name, so let's
	 * use '_' in arc pct name as it goes to kernel PMU event prefix.
	 */
	return perf_pmu_register(&arc_slc_pmu->pmu, "arc_slc_pmu", -1);
}

static const struct of_device_id arc_pmu_slc_match[] = {
	{ .compatible = "snps,arcv2-slc-pmu" },
	{},
};
MODULE_DEVICE_TABLE(of, arc_pmu_slc_match);

static struct platform_driver arc_pmu_slc_driver = {
	.driver	= {
		.name = "ARCv2-slc-PMU",
		.of_match_table = of_match_ptr(arc_pmu_slc_match),
	},
	.probe = arc_pmu_slc_device_probe,
};

module_platform_driver(arc_pmu_slc_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bolsh@synopsys.com");
MODULE_DESCRIPTION("ARCv2 PMU driver for system level cache");
