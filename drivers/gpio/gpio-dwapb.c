/*
 * Copyright (c) 2011 Jamie Iles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * All enquiries to support@picochip.com
 */
#include <linux/init.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/basic_mmio_gpio.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>

#define INT_ENABLE_REG_OFFS	0x30
#define INT_MASK_REG_OFFS	0x34
#define INT_TYPE_REG_OFFS	0x38
#define INT_POLARITY_REG_OFFS	0x3c
#define INT_STATUS_REG_OFFS	0x40
#define EOI_REG_OFFS		0x4c

struct dwapb_gpio;

struct dwapb_gpio_bank {
	struct bgpio_chip	bgc;
	bool			is_registered;
	struct dwapb_gpio	*gpio;
};

struct dwapb_gpio {
	struct device		*dev;
	void __iomem		*regs;
	struct dwapb_gpio_bank	*banks;
	unsigned int		nr_banks;
	struct irq_chip_generic	*irq_gc;
	struct irq_domain	*domain;
	unsigned long		toggle_edge;
	unsigned int		first_irq_pin;
	unsigned int		last_irq_pin;
};

static unsigned int dwapb_gpio_nr_banks(struct device_node *of_node)
{
	unsigned int nr_banks = 0;
	struct device_node *np;

	for_each_child_of_node(of_node, np)
		++nr_banks;

	return nr_banks;
}

static int dwapb_gpio_to_irq(struct gpio_chip *gc, unsigned offset)
{
	struct bgpio_chip *bgc = to_bgpio_chip(gc);
	struct dwapb_gpio_bank *bank = container_of(bgc, struct
						    dwapb_gpio_bank, bgc);
	struct dwapb_gpio *gpio = bank->gpio;

	return irq_find_mapping(gpio->domain, offset - gpio->first_irq_pin);
}

static void dwapb_toggle_trigger(struct dwapb_gpio *gpio, unsigned int offs)
{
	u32 v = ioread32(gpio->regs + INT_TYPE_REG_OFFS);

	if (gpio_get_value(gpio->banks[0].bgc.gc.base + offs))
		v &= ~BIT(offs);
	else
		v |= BIT(offs);

	iowrite32(v, gpio->regs + INT_TYPE_REG_OFFS);
}

static void dwapb_irq_handler(u32 irq, struct irq_desc *desc)
{
	struct dwapb_gpio *gpio = irq_get_handler_data(irq);
	u32 irq_status = ioread32(gpio->regs + INT_STATUS_REG_OFFS);

	/* mask out bits that don't belong to us */
	irq_status &= IRQ_MSK((gpio->last_irq_pin -
			       gpio->first_irq_pin) + 1) << gpio->first_irq_pin;

	while (irq_status) {
		int irqoffset = fls(irq_status) - 1;
		int irq = irq_find_mapping(gpio->domain,
					   irqoffset - gpio->first_irq_pin);

		generic_handle_irq(irq);
		irq_status &= ~(1 << irqoffset);

		if (gpio->toggle_edge & BIT(irqoffset))
			dwapb_toggle_trigger(gpio, irqoffset);
	}
}

static void dwapb_irq_disable(struct irq_data *d)
{
	struct irq_chip_generic *gc = irq_data_get_irq_chip_data(d);
	struct dwapb_gpio *gpio = gc->private;
	int bit = d->hwirq + gpio->first_irq_pin;

	u32 val = ioread32(gpio->regs + INT_MASK_REG_OFFS);
	val |= 1 << bit;
	iowrite32(val, gpio->regs + INT_MASK_REG_OFFS);
}

static void dwapb_irq_enable(struct irq_data *d)
{
	struct irq_chip_generic *gc = irq_data_get_irq_chip_data(d);
	struct dwapb_gpio *gpio = gc->private;
	int bit = d->hwirq + gpio->first_irq_pin;

	u32 val = ioread32(gpio->regs + INT_MASK_REG_OFFS);
	val &= ~(1 << bit);
	iowrite32(val, gpio->regs + INT_MASK_REG_OFFS);
}

static int dwapb_irq_set_type(struct irq_data *d, u32 type)
{
	struct irq_chip_generic *gc = irq_data_get_irq_chip_data(d);
	struct dwapb_gpio *gpio = gc->private;
	int bit = d->hwirq + gpio->first_irq_pin;
	unsigned long level, polarity;

	if (type & ~(IRQ_TYPE_EDGE_RISING | IRQ_TYPE_EDGE_FALLING |
		     IRQ_TYPE_LEVEL_HIGH | IRQ_TYPE_LEVEL_LOW))
		return -EINVAL;

	level = ioread32(gpio->regs + INT_TYPE_REG_OFFS);
	polarity = ioread32(gpio->regs + INT_POLARITY_REG_OFFS);

	gpio->toggle_edge &= ~BIT(bit);
	if (type & IRQ_TYPE_EDGE_BOTH) {
		gpio->toggle_edge |= BIT(bit);
		level |= (1 << bit);
		dwapb_toggle_trigger(gpio, bit);
	} else if (type & IRQ_TYPE_EDGE_RISING) {
		level |= (1 << bit);
		polarity |= (1 << bit);
	} else if (type & IRQ_TYPE_EDGE_FALLING) {
		level |= (1 << bit);
		polarity &= ~(1 << bit);
	} else if (type & IRQ_TYPE_LEVEL_HIGH) {
		level &= ~(1 << bit);
		polarity |= (1 << bit);
	} else if (type & IRQ_TYPE_LEVEL_LOW) {
		level &= ~(1 << bit);
		polarity &= ~(1 << bit);
	}

	iowrite32(level, gpio->regs + INT_TYPE_REG_OFFS);
	iowrite32(polarity, gpio->regs + INT_POLARITY_REG_OFFS);

	return 0;
}

static int dwapb_create_irqchip(struct dwapb_gpio *gpio,
				struct dwapb_gpio_bank *bank,
				unsigned int irq_base)
{
	struct irq_chip_type *ct;
	int nirq;

	gpio->irq_gc = irq_alloc_generic_chip("gpio-dwapb", 1, irq_base,
					      gpio->regs, handle_level_irq);
	if (!gpio->irq_gc)
		return -EIO;

	gpio->irq_gc->private = gpio;
	ct = gpio->irq_gc->chip_types;
	ct->chip.irq_ack = irq_gc_ack_set_bit;
	ct->chip.irq_mask = dwapb_irq_disable;
	ct->chip.irq_unmask = dwapb_irq_enable;
	ct->chip.irq_set_type = dwapb_irq_set_type;
	ct->chip.irq_enable = dwapb_irq_enable;
	ct->chip.irq_disable = dwapb_irq_disable;
	ct->regs.ack = EOI_REG_OFFS;
	ct->regs.mask = INT_MASK_REG_OFFS;
	nirq = gpio->last_irq_pin - gpio->first_irq_pin + 1;
	irq_setup_generic_chip(gpio->irq_gc, IRQ_MSK(nirq),
			       IRQ_GC_INIT_NESTED_LOCK, IRQ_NOREQUEST,
			       IRQ_LEVEL);

	gpio->domain = irq_domain_add_simple(of_node_get(bank->bgc.gc.of_node),
					     nirq, irq_base,
					     &irq_domain_simple_ops, gpio);
	return 0;
}

static void dwapb_init_irqs(struct dwapb_gpio *gpio, int nirq)
{
	uint32_t i;

	/* mask all IRQs */
	i = ioread32(gpio->regs + INT_MASK_REG_OFFS);
	iowrite32(i | (IRQ_MSK(nirq) << gpio->first_irq_pin),
		  gpio->regs + INT_MASK_REG_OFFS);

	/* enable all IRQs */
	i = ioread32(gpio->regs + INT_ENABLE_REG_OFFS);
	iowrite32(i | (IRQ_MSK(nirq) << gpio->first_irq_pin),
		  gpio->regs + INT_ENABLE_REG_OFFS);

	/* level IRQs by default */
	i = ioread32(gpio->regs + INT_TYPE_REG_OFFS);
	iowrite32(i & ~(IRQ_MSK(nirq) << gpio->first_irq_pin),
		  gpio->regs + INT_TYPE_REG_OFFS);

	/* active high by default */
	i = ioread32(gpio->regs + INT_POLARITY_REG_OFFS);
	iowrite32(i | (IRQ_MSK(nirq) << gpio->first_irq_pin),
		  gpio->regs + INT_POLARITY_REG_OFFS);
}

static int dwapb_configure_irqs(struct dwapb_gpio *gpio,
				struct dwapb_gpio_bank *bank)
{
	unsigned int m, irq, nirq, ngpio = bank->bgc.gc.ngpio;
	int irq_base;

	gpio->first_irq_pin = 0;
	gpio->last_irq_pin = ngpio - 1;
	of_property_read_u32(bank->bgc.gc.of_node, "first-irq-pin",
			     &gpio->first_irq_pin);
	of_property_read_u32(bank->bgc.gc.of_node, "last-irq-pin",
			     &gpio->last_irq_pin);

	nirq = gpio->last_irq_pin - gpio->first_irq_pin + 1;

	dwapb_init_irqs(gpio, nirq);

	for (m = 0; m < nirq; ++m) {
		irq = irq_of_parse_and_map(bank->bgc.gc.of_node, m);
		if (!irq && m == 0) {
			dev_warn(gpio->dev, "no irq for bank %s\n",
				 bank->bgc.gc.of_node->full_name);
			return -ENXIO;
		} else if (!irq) {
			break;
		}

		irq_set_handler_data(irq, gpio);
		irq_set_chained_handler(irq, dwapb_irq_handler);
	}
	bank->bgc.gc.to_irq = dwapb_gpio_to_irq;

	irq_base = irq_alloc_descs(-1, 0, nirq, NUMA_NO_NODE);
	if (irq_base < 0)
		return irq_base;

	if (dwapb_create_irqchip(gpio, bank, irq_base))
		goto out_free_descs;

	return 0;

out_free_descs:
	irq_free_descs(irq_base, nirq);

	return -EIO;
}

static int dwapb_gpio_add_bank(struct dwapb_gpio *gpio,
			       struct device_node *bank_np,
			       unsigned int offs)
{
	struct dwapb_gpio_bank *bank;
	u32 bank_idx, ngpio;
	int err;

	if (of_property_read_u32(bank_np, "bank-idx", &bank_idx)) {
		dev_err(gpio->dev, "invalid bank index for %s\n",
			bank_np->full_name);
		return -EINVAL;
	}
	bank = &gpio->banks[offs];
	bank->gpio = gpio;

	if (of_property_read_u32(bank_np, "nr-gpio", &ngpio)) {
		dev_err(gpio->dev, "failed to get number of gpios for %s\n",
			bank_np->full_name);
		return -EINVAL;
	}

	err = bgpio_init(&bank->bgc, gpio->dev, 4,
			 gpio->regs + 0x50 + (bank_idx * 0x4),
			 gpio->regs + 0x00 + (bank_idx * 0xc),
			 NULL, gpio->regs + 0x04 + (bank_idx * 0xc), NULL,
			 false);
	if (err) {
		dev_err(gpio->dev, "failed to init gpio chip for %s\n",
			bank_np->full_name);
		return err;
	}

	bank->bgc.gc.ngpio = ngpio;
	bank->bgc.gc.of_node = bank_np;

	/*
	 * Only bank A can provide interrupts in all configurations of the IP.
	 */
	if (bank_idx == 0 &&
	    of_get_property(bank_np, "interrupt-controller", NULL))
		dwapb_configure_irqs(gpio, bank);

	err = gpiochip_add(&bank->bgc.gc);
	if (err)
		dev_err(gpio->dev, "failed to register gpiochip for %s\n",
			bank_np->full_name);
	else
		bank->is_registered = true;

	return err;
}

static void dwapb_gpio_unregister(struct dwapb_gpio *gpio)
{
	unsigned int m;

	for (m = 0; m < gpio->nr_banks; ++m)
		if (gpio->banks[m].is_registered)
			WARN_ON(gpiochip_remove(&gpio->banks[m].bgc.gc));
}

static int dwapb_gpio_probe(struct platform_device *pdev)
{
	struct resource *res;
	struct dwapb_gpio *gpio;
	struct device_node *np;
	int err;
	unsigned int offs = 0;

	gpio = devm_kzalloc(&pdev->dev, sizeof(*gpio), GFP_KERNEL);
	if (!gpio)
		return -ENOMEM;
	gpio->dev = &pdev->dev;

	gpio->nr_banks = dwapb_gpio_nr_banks(pdev->dev.of_node);
	if (!gpio->nr_banks)
		return -EINVAL;
	gpio->banks = devm_kzalloc(&pdev->dev, gpio->nr_banks *
				   sizeof(*gpio->banks), GFP_KERNEL);
	if (!gpio->banks)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	gpio->regs = devm_request_and_ioremap(&pdev->dev, res);
	if (!gpio->regs)
		return -ENOMEM;

	for_each_child_of_node(pdev->dev.of_node, np) {
		err = dwapb_gpio_add_bank(gpio, np, offs++);
		if (err)
			goto out_unregister;
	}
	platform_set_drvdata(pdev, gpio);

	return 0;

out_unregister:
	dwapb_gpio_unregister(gpio);

	return err;
}

static const struct of_device_id dwapb_of_match_table[] = {
	{ .compatible = "snps,dw-apb-gpio" },
	{ /* Sentinel */ }
};

static struct platform_driver dwapb_gpio_driver = {
	.driver		= {
		.name	= "gpio-dwapb",
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(dwapb_of_match_table),
	},
	.probe		= dwapb_gpio_probe,
};

static int __init dwapb_gpio_init(void)
{
	return platform_driver_register(&dwapb_gpio_driver);
}
postcore_initcall(dwapb_gpio_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jamie Iles");
MODULE_DESCRIPTION("Synopsys DesignWare APB GPIO driver");
