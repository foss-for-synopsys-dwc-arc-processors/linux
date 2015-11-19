/*
 * PCIe RC driver for Synopsys Designware Core
 *
 * Copyright (C) 2015-2016 Synopsys, Inc. (www.synopsys.com)
 *
 * Authors: Manjunath Bettegowda <manjumb@synopsys.com>,
 *	    Jie Deng <jiedeng@synopsys.com>
 *	    Joao Pinto <jpinto@synopsys.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/resource.h>
#include <linux/signal.h>
#include <linux/types.h>

#include "pcie-designware.h"

#define to_snpsdev_pcie(x)	container_of(x, struct snpsdev_pcie, pp)

struct snpsdev_pcie {
	void __iomem		*mem_base; /* Memory Base to access Core's [RC] Config Space Layout */
	struct pcie_port	pp;        /* RC Root Port specific structrue - DWC_PCIE_RC stuff */
};

#define SIZE_1GB 0x40000000
#define PCI_EQUAL_CONTROL_PHY 0x00000707

/* PCIe Port Logic registers (memory-mapped) */
#define PLR_OFFSET 0x700
#define PCIE_PHY_DEBUG_R0 (PLR_OFFSET + 0x28) /* 0x728 */
#define PCIE_PHY_DEBUG_R1 (PLR_OFFSET + 0x2c) /* 0x72c */

/* PCIE PHY CONTROL REGISTER: Useful for cfg_phy_control GPIO outputs */
#define PCIE_PHY_CTRL (PLR_OFFSET + 0x114)    /* 0x814 */
/* PCIE PHY STATUS REGISTER: Useful for phy_cfg_status GPIO inputs */
#define PCIE_PHY_STAT (PLR_OFFSET + 0x110)    /* 0x810 */

static void snpsdev_pcie_fixup_bridge(struct pci_dev *dev)
{
	u32 slot_cap;
	u16 caps_reg = pcie_caps_reg(dev) | PCI_EXP_FLAGS_SLOT;
	pcie_capability_write_word(dev, PCI_EXP_FLAGS, caps_reg);
	dev->pcie_flags_reg = caps_reg;

	pcie_capability_read_dword(dev, PCI_EXP_SLTCAP, &slot_cap);
	slot_cap = slot_cap & (~PCI_EXP_SLTCAP_SPLV);
	slot_cap = slot_cap | (0x30 << 7);
	pcie_capability_write_dword(dev, PCI_EXP_SLTCAP, slot_cap);

	if (pcibios_enable_device(dev, ~0) < 0) {
		pr_err("PCI: synopsys device enable failed\n");
		return;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_ANY_ID, PCI_ANY_ID, snpsdev_pcie_fixup_bridge);

static void snpsdev_pcie_fixup_res(struct pci_dev *dev)
{
	struct resource *res;
	resource_size_t size;
	int bar;

	for (bar = 0; bar < 6; bar++) {
		res = dev->resource + bar;
		size = resource_size(res);

		if (size == SIZE_1GB)
		{
			res->start = 0;
			res->end   = 0;
			res->flags = 0;
		}
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_ANY_ID, PCI_ANY_ID, snpsdev_pcie_fixup_res);

/* This handler was created for future work */
static irqreturn_t snpsdev_pcie_irq_handler(int irq, void *arg)
{
	return IRQ_NONE;
}

static irqreturn_t snpsdev_pcie_msi_irq_handler(int irq, void *arg)
{
	struct pcie_port *pp = arg;

	dw_handle_msi_irq(pp);

	return IRQ_HANDLED;
}

static void snpsdev_pcie_init_phy(struct pcie_port *pp)
{
	/* write Lane 0 Equalization Control fields register */
	writel(PCI_EQUAL_CONTROL_PHY,pp->dbi_base + 0x154);
}

static int snpsdev_pcie_deassert_core_reset(struct pcie_port *pp)
{
	return 0;
}

/*
 * snpsdev_pcie_host_init()
 * Platform specific host/RC initialization
 * 	a. Assert the core reset
 * 	b. Assert and deassert phy reset and initialize the phy
 * 	c. De-Assert the core reset
 * 	d. Initializet the Root Port (BARs/Memory Or IO/ Interrupt/ Commnad Reg)
 * 	e. Initiate Link startup procedure
 *
 */
static void snpsdev_pcie_host_init(struct pcie_port *pp)
{
	int count = 0;

	/* Initialize Phy (Reset/poweron/control-inputs ) */
	snpsdev_pcie_init_phy(pp);

	/* de-assert core reset */
	snpsdev_pcie_deassert_core_reset(pp);

	/*We expect the PCIE Link to be up by this time*/
	dw_pcie_setup_rc(pp);

	/*Start LTSSM here*/
	dw_pcie_link_retrain(pp);

	/* Check for Link up indication */
	while (!dw_pcie_link_up(pp)) {
		usleep_range(1000,1100);
		count++;
		if (count == 20) {
			dev_err(pp->dev, "phy link never came up\n");
			dev_dbg(pp->dev,
				"PL_DEBUG0: 0x%08x, DEBUG_R1: 0x%08x\n",
				readl(pp->dbi_base + PCIE_PHY_DEBUG_R0),
				readl(pp->dbi_base + PCIE_PHY_DEBUG_R1));
			break;
		}
	}

	if (IS_ENABLED(CONFIG_PCI_MSI))
		dw_pcie_msi_init(pp);

	return;
}
/**
 *
 * Let all outof band signalling be handled by cfg_phy_control[31:0]
 * which is selected through optional config attribute PHY_CONTROL_REG
 *
 * Monitor cxpl_debug_info as required to take necessary action
 * This is available in the register PCIE_PHY_DEBUG_R0 & PCIE_PHY_DEBUG_R1
 *
 */
static int snpsdev_pcie_link_up(struct pcie_port *pp)
{
	u32 status;

	/* Bit number 36: reports LTSSM PHY Link UP; Available in bit 3 of
         *  PCIE_PHY_DEBUG_R1 */
	status = readl(pp->dbi_base + PCIE_PHY_DEBUG_R1) & (0x1 << 4);
	if(status != 0)
		return 1;

	/* TODO: Now Link is in L0; Initiate GEN2/GEN3 migration if RC Supports */
	return 0;
}


/**
 * This is RC operation structure
 * snpsdev_pcie_link_up: the function which initiates the phy link up procedure
 * snpsdev_pcie_host_init: the function whihc does the host/RC Root port initialization
 */
static struct pcie_host_ops snpsdev_pcie_host_ops = {
	.link_up = snpsdev_pcie_link_up,
	.host_init = snpsdev_pcie_host_init,
};

/**
 * snpsdev_add_pcie_port
 * This function
 * a. installs the interrupt handler
 * b. registers host operations int he pcie_port structure
 */
static int snpsdev_add_pcie_port(struct pcie_port *pp, struct platform_device *pdev)
{
	int ret;

	pp->irq = platform_get_irq(pdev, 1);

	if (pp->irq < 0) {
		if (pp->irq != -EPROBE_DEFER)
			dev_err(&pdev->dev, "cannot get irq\n");
		return pp->irq;
	}

	ret = devm_request_irq(&pdev->dev, pp->irq, snpsdev_pcie_irq_handler,
				IRQF_SHARED, "snpsdev-pcie", pp);

	if (ret) {
		dev_err(&pdev->dev, "failed to request irq\n");
		return ret;
	}

	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		pp->msi_irq = platform_get_irq(pdev, 0);

		if (pp->msi_irq < 0) {
			if (pp->msi_irq != -EPROBE_DEFER)
				dev_err(&pdev->dev, "cannot get msi irq\n");
			return pp->msi_irq;
		}

		ret = devm_request_irq(&pdev->dev, pp->msi_irq,
					snpsdev_pcie_msi_irq_handler,
					IRQF_SHARED, "snpsdev-pcie-msi", pp);
		if (ret) {
			dev_err(&pdev->dev, "failed to request msi irq\n");
			return ret;
		}
	}

	pp->root_bus_nr = -1;
	pp->ops = &snpsdev_pcie_host_ops;

	/* Below function:
	 * Checks for range property from DT
	 * Gets the IO and MEMORY and CONFIG-Space ranges from DT
	 * Does IOREMAPS on the physical addresses
	 * Gets the num-lanes from DT
	 * Gets MSI capability from DT
	 * Calls the platform specific host initialization
	 * Program the correct class, BAR0, Link width,  in Config space
	 * Then it calls pci common init routine
	 * Then it calls funtion to assign "unassigend reources"
         */
	ret = dw_pcie_host_init(pp);
	if (ret) {
		dev_err(&pdev->dev, "failed to initialize host\n");
		return ret;
	}

	return 0;
}

/**
 * snpsdev_pcie_rc_probe()
 * This function gets called as part of pcie registration. if the id matches
 * the platform driver framework will call this function.
 *
 * @pdev: Pointer to the platform_device structure
 *
 * Returns zero on success; Negative errorno on failure
 */
static int __init snpsdev_pcie_rc_probe(struct platform_device *pdev)
{
	struct snpsdev_pcie *snpsdev_pcie;
	struct pcie_port *pp;
	struct resource *dwc_pcie_rc_res;  /* Resource from DT */
	int ret;

	snpsdev_pcie = devm_kzalloc(&pdev->dev, sizeof(*snpsdev_pcie), GFP_KERNEL);
	if (!snpsdev_pcie) {
		dev_err(&pdev->dev, "no memory for snpsdev pcie\n");
		return -ENOMEM;
	}

	pp = &snpsdev_pcie->pp;
	pp->dev = &pdev->dev;

	dwc_pcie_rc_res= platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!dwc_pcie_rc_res) {
		dev_err(&pdev->dev, "dwc_pcie_rc_res resource not found\n");
		return -ENODEV;
	}

	snpsdev_pcie->mem_base = devm_ioremap_resource(&pdev->dev, dwc_pcie_rc_res);
	if (IS_ERR(snpsdev_pcie->mem_base)) {
		ret = PTR_ERR(snpsdev_pcie->mem_base);
		return ret;
	}
	pp->dbi_base = snpsdev_pcie->mem_base;

	ret = snpsdev_add_pcie_port(pp, pdev);
	if (ret < 0)
		return ret;

	platform_set_drvdata(pdev, snpsdev_pcie);

	return 0;
}

static int __exit snpsdev_pcie_rc_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id snpsdev_pcie_rc_of_match[] = {
	{ .compatible = "snps,pcie-snpsdev", },
	{},
};
MODULE_DEVICE_TABLE(of, snpsdev_pcie_rc_of_match);

static struct platform_driver snpsdev_pcie_rc_driver = {
	.remove		= __exit_p(snpsdev_pcie_rc_remove),
	.driver = {
		.name	= "pcie-snpsdev",
		.owner	= THIS_MODULE,
		.of_match_table = snpsdev_pcie_rc_of_match,
	},
};

static int __init snpsdev_pcie_init(void)
{
	return platform_driver_probe(&snpsdev_pcie_rc_driver, snpsdev_pcie_rc_probe);
}
subsys_initcall(snpsdev_pcie_init);

MODULE_AUTHOR("Manjunath Bettegowda <manjumb@synopsys.com>");
MODULE_DESCRIPTION("Platform Driver for Synopsys Device");
MODULE_LICENSE("GPL v2");
