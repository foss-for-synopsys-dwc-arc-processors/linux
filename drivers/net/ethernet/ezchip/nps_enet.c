/*******************************************************************************

  EZchip Network Linux driver
  Copyright(c) 2012 EZchip Technologies.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

*******************************************************************************/

#include <linux/platform_device.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include "nps_enet.h"

#define  DRV_NAME      "eth"
#define  DRV_VERSION   "0.1"
#define  DRV_RELDATE   "11.Feb.2012"

MODULE_AUTHOR("Tal Zilcer <talz@ezchip.com>");
MODULE_DESCRIPTION("EZCHIP NPS-HE LAN driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

static char version[] __devinitdata =
	DRV_NAME "driver version " DRV_VERSION " (" DRV_RELDATE ")\n";

struct net_device *npsdev;
struct sockaddr mac_addr = { 0, {0x84, 0x66, 0x46, 0x88, 0x63, 0x33} };

#define array_int_len(x) ((x + 3) >> 2)

static int ez_net_set_mac_address(struct net_device *netdev, void *p)
{
	int res;
	EZ_NET_PRIV *netPriv = netdev_priv(netdev);
	struct sockaddr *x = (struct sockaddr *)p;
	char *uc_addr = (char *)x->sa_data;

	netif_info(netPriv, hw, netdev,
			"new MAC addr %02x:%02x:%02x:%02x:%02x:%02x\n",
			uc_addr[0]&0x0FF, uc_addr[1]&0x0FF, uc_addr[2]&0x0FF,
			uc_addr[3]&0x0FF, uc_addr[4]&0x0FF, uc_addr[5]&0x0FF);

	res = eth_mac_addr(netdev, p);
	if (!res)
		memcpy(netPriv->address, uc_addr, ETH_ALEN);

	return res;
}


static inline void ez_net_hw_enable_control(void)
{
	REG_GEMAC_TX_CTL &= ~(TX_CTL_RESET);
	REG_GEMAC_RX_CTL &= ~(RX_CTL_RESET);
}

static inline void ez_net_hw_disable_control(void)
{
	REG_GEMAC_TX_CTL |= TX_CTL_RESET;
	REG_GEMAC_RX_CTL |= RX_CTL_RESET;
}

static void ez_net_send_buf(struct net_device *netdev,
				struct sk_buff *skb, short length)
{

	int i;
	int k;
	int dummy_buf;
	unsigned int *srcData = (unsigned int *)virt_to_phys(skb->data);

	k = array_int_len(length);

	/* Check alignment of source */
	if (((int)srcData & 0x3) == 0) {
		for (i = 0; i < k; i++)
			REG_GEMAC_TXBUF_DATA = srcData[i];
	} else { /* Not aligned */
		for (i = 0; i < k; i++) {
			/*
			 * Tx buffer is a FIFO
			 * so we have to write all 4 bytes at once
			 */
			memcpy(&dummy_buf, srcData+i, EZ_NET_REG_SIZE);
			REG_GEMAC_TXBUF_DATA = dummy_buf;
		}
	}
	/* Write the length of the Frame */
	REG_GEMAC_TX_CTL = (REG_GEMAC_TX_CTL & ~(TX_CTL_LENGTH_MASK)) | length;
	/* Send Frame */
	REG_GEMAC_TX_CTL |= TX_CTL_BUSY;

	return;
}

static int ez_net_open(struct net_device *netdev)
{
	EZ_NET_PRIV *netPriv = netdev_priv(netdev);

	if (netPriv->status != EZ_NET_DEV_OFF)
		return -EAGAIN;

	ez_net_hw_enable_control();

	netPriv->status = EZ_NET_DEV_ON;
	/* Driver can now transmit frames */
	netif_start_queue(netdev);
	return 0;
}

static int ez_net_stop(struct net_device *netdev)
{
	EZ_NET_PRIV *netPriv = netdev_priv(netdev);

	netif_stop_queue(netdev);

	ez_net_hw_disable_control();

	if (netPriv->status != EZ_NET_DEV_OFF) {
		netPriv->status = EZ_NET_DEV_OFF;
		netPriv->down_event++;
	}
	return 0;
}

static netdev_tx_t ez_net_start_xmit(struct sk_buff *skb,
					struct net_device *netdev)
{
	EZ_NET_PRIV *netPriv = netdev_priv(netdev);
	short length = skb->len;

	if (skb->len < ETH_ZLEN) {
		if (unlikely(skb_padto(skb, ETH_ZLEN) != 0))
			return NETDEV_TX_OK;
		length = ETH_ZLEN;
	}

	netPriv->packet_len = length;
	ez_net_send_buf(netdev, skb, length);

	dev_kfree_skb(skb);
	/* This driver handles one frame at a time  */
	netif_stop_queue(netdev);
	/* Enable LAN TX end IRQ  */
	enable_irq(IRQ_LAN_TX_LINE);
	return NETDEV_TX_OK;
}

static struct net_device_stats *ez_net_get_stats(struct net_device *netdev)
{
	return &netdev->stats;
}

static int ez_net_change_mtu(struct net_device *netdev, int new_mtu)
{
	EZ_NET_PRIV *netPriv = netdev_priv(netdev);

	netif_printk(netPriv, hw, KERN_INFO, netdev ,
		   "mtu change from %d to %d\n",
		   (int)netdev->mtu, new_mtu);

	if ((new_mtu < ETH_ZLEN) || (new_mtu > EZ_NET_ETH_PKT_SZ))
		return -EINVAL;

	netdev->mtu = new_mtu;

	return 0;
}

static void ez_net_set_rx_mode(struct net_device *netdev)
{
	EZ_NET_PRIV *netPriv = netdev_priv(netdev);

	if (netdev->flags & IFF_PROMISC)
		netPriv->rx_mode = EZ_NET_PROMISC_MODE;
	else
		netPriv->rx_mode = EZ_NET_BRODCAST_MODE;

	return;
}

static int ez_net_do_ioctl(struct net_device *netdev,
				 struct ifreq *ifr, int cmd)
{
	switch (cmd) {
	case SIOCSIFTXQLEN:
		if (ifr->ifr_qlen < 0)
			return -EINVAL;

		netdev->tx_queue_len = ifr->ifr_qlen;
		break;

	case SIOCGIFTXQLEN:
		ifr->ifr_qlen = netdev->tx_queue_len;
		break;

	case SIOCSIFFLAGS:      /* Set interface flags */
		return dev_change_flags(netdev, ifr->ifr_flags);

	case SIOCGIFFLAGS:      /* Get interface flags */
		ifr->ifr_flags = (short) dev_get_flags(netdev);
		break;

	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static void ez_net_tx_timeout(struct net_device *netdev)
{
	EZ_NET_PRIV *netPriv = netdev_priv(netdev);

	netif_printk(netPriv, tx_err, KERN_DEBUG, netdev,
		     "transmission timed out\n");
}

static const struct net_device_ops nps_netdev_ops = {
	.ndo_open		= ez_net_open,
	.ndo_stop		= ez_net_stop,
	.ndo_start_xmit		= ez_net_start_xmit,
	.ndo_get_stats		= ez_net_get_stats,
	.ndo_set_mac_address	= ez_net_set_mac_address,
	.ndo_set_rx_mode	= ez_net_set_rx_mode,
	.ndo_change_mtu		= ez_net_change_mtu,
	.ndo_do_ioctl		= ez_net_do_ioctl,
	.ndo_tx_timeout		= ez_net_tx_timeout,

};

static void clean_rx_fifo(void)
{
	int i;
	int length;
	int k;

	length = REG_GEMAC_RX_CTL & RX_CTL_LENGTH_MASK;
	k = array_int_len(length);
	for (i = 0; i < k; i++)
		length = REG_GEMAC_RXBUF_DATA;

}

static void read_rx_fifo(EZ_NET_PRIV *netPriv, unsigned int *dest)
{
	int i;
	int length;
	unsigned int dummy_buf;
	int k;

	length = REG_GEMAC_RX_CTL & RX_CTL_LENGTH_MASK;
	k = array_int_len(length);

	if (((int)dest & 0x3) == 0) {
		for (i = 0; i < k; i++)
			dest[i] = REG_GEMAC_RXBUF_DATA;
	} else {
		for (i = 0; i < k; i++) {
			dummy_buf = REG_GEMAC_RXBUF_DATA;
			memcpy(dest+i, &dummy_buf, EZ_NET_REG_SIZE);
		}
	}
}

static bool isValidEnterFrame(struct net_device *netdev, char *bufRecv)
{
	char mac_brodcast[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	EZ_NET_PRIV *netPriv = netdev_priv(netdev);

	/* Check destination MAC address */
	if (memcmp(bufRecv, netPriv->address, ETH_ALEN) == 0)
		return true;

	/* Value 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF for broadcast */
	if (memcmp(bufRecv, mac_brodcast, ETH_ALEN) == 0)
		return true;

	/* Promisc mode */
	if (netPriv->rx_mode == EZ_NET_PROMISC_MODE)
		return true;

	return false;
}


static irqreturn_t ez_net_rx_irq(int irq, void *dev_id)
{
	struct net_device *netdev;
	EZ_NET_PRIV *netPriv;
	struct sk_buff *skb;
	int curRxCtl;
	int frame_len;

	netdev = dev_id;
	if (unlikely(!netdev))
		return IRQ_NONE;

	netPriv = netdev_priv(netdev);
	curRxCtl = REG_GEMAC_RX_CTL;
	frame_len = curRxCtl & RX_CTL_LENGTH_MASK;

	/* Check RX error */
	if ((curRxCtl & RX_CTL_ERROR) != 0) {
		netdev->stats.rx_errors++;
		goto rx_irq_error;
	}

	/* Check RX crc error */
	if ((curRxCtl & RX_CTL_CRC) != 0) {
		netdev->stats.rx_crc_errors++;
		netdev->stats.rx_dropped++;
		goto rx_irq_error;
	}

	/* Check Frame length (MAX 1.5k Min 64b) */
	if (unlikely(frame_len > EZ_NET_LAN_BUFFER_SIZE
			|| frame_len < ETH_ZLEN)) {
		netdev->stats.rx_dropped++;
		goto rx_irq_error;
	}

	skb = netdev_alloc_skb_ip_align(netdev, (frame_len + 32));

	/* Check skb allocation */
	if (unlikely(skb == NULL)) {
		netdev->stats.rx_errors++;
		netdev->stats.rx_dropped++;
		goto rx_irq_error;
	}

	read_rx_fifo(netPriv, (unsigned int *)skb->data);

	if (isValidEnterFrame(netdev, skb->data) == false) {
		dev_kfree_skb_irq(skb);
	} else {
		skb_put(skb, frame_len);
		skb->dev = netdev;
		skb->protocol = eth_type_trans(skb, netdev);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		netif_rx(skb);
		netdev->stats.rx_packets++;
		netdev->stats.rx_bytes += frame_len;
	}
	goto rx_irq_finish;

rx_irq_error:
	/* Clean RX fifo */
	clean_rx_fifo();

rx_irq_finish:
	/* Clean RX CTL register */
	REG_GEMAC_RX_CTL = 0;
	return IRQ_HANDLED;
}

static irqreturn_t ez_net_tx_irq(int irq, void *dev_id)
{
	struct net_device *netdev = dev_id;
	EZ_NET_PRIV *netPriv = netdev_priv(netdev);

	/*
	 * This is because we don't want to get TX end interrupt
	 * until we send a frame ( TX_CTL CT must be 0  )
	 */
	disable_irq_nosync(IRQ_LAN_TX_LINE);

	if (unlikely(!netdev || netPriv->status == EZ_NET_DEV_OFF))
		return IRQ_NONE;

	/* Check Tx error */
	if (unlikely(REG_GEMAC_TX_CTL & TX_CTL_ERROR) != 0) {
		netdev->stats.tx_errors++;
		/* clean TX CTL error */
		REG_GEMAC_TX_CTL &= ~(TX_CTL_ERROR);
	} else {
		netdev->stats.tx_packets++;
		netdev->stats.tx_bytes += netPriv->packet_len;
	}

	/* In ez_net_start_xmit we disabled sending frames*/
	netif_wake_queue(netdev);

	return IRQ_HANDLED;
}

static int __devinit ez_net_probe(struct platform_device *pdev)
{
	struct net_device *netdev;
	EZ_NET_PRIV *netPriv;
	int err;

	if (!pdev) {
		printk(KERN_ERR "%s: ERROR - no platform device defined\n",
			__func__);
		return -EINVAL;
	}

	netdev = (struct net_device *)alloc_etherdev(sizeof(EZ_NET_PRIV));
	if (!netdev)
		return -ENOMEM;

	netPriv = netdev_priv(netdev);

	/* The EZ NET specific entries in the device structure. */
	netdev->netdev_ops     = &nps_netdev_ops;
	netdev->watchdog_timeo = (400*HZ/1000);
	netdev->ml_priv = netPriv;

	/* initialize driver private data structure. */
	netPriv->status = EZ_NET_DEV_OFF;
	netPriv->msg_enable = 1; /* enable messages for netif_printk */

	netif_info(netPriv, hw, netdev, "%s: port %s\n",
			 __func__, netdev->name);

	/* config GEMAC register */
	REG_GEMAC_MAC_CFG = GEMAC_CFG_INIT_VALUE;
	REG_GEMAC_RX_CTL = 0;
	ez_net_hw_disable_control();

	/* set kernel MAC address to dev */
	ez_net_set_mac_address(netdev, &mac_addr);

	/* irq Rx allocation */
	err = request_irq(IRQ_LAN_RX_LINE, ez_net_rx_irq,
			 0 , "eth0-rx", netdev);
	if (err) {
		netif_err(netPriv, probe, netdev,
			"EZnet: Fail to allocate IRQ %d - err %d\n",
			IRQ_LAN_RX_LINE, err);
		goto ez_net_probe_error;
	}

	/* irq Tx allocation */
	err = request_irq(IRQ_LAN_TX_LINE, ez_net_tx_irq,
			0 , "eth0-tx", netdev);
	if (err) {
		netif_err(netPriv, probe, netdev,
			"EZnet: Fail to allocate IRQ %d - err %d\n",
			IRQ_LAN_TX_LINE, err);
		goto ez_net_probe_error;

	}

	/* We dont support MULTICAST */
	netdev->flags &= ~IFF_MULTICAST;

	/*
	 * Register the driver
	 * Should  be the last thing in probe
	 */
	err = register_netdev(netdev);
	if (err != 0) {
		netif_err(netPriv, probe, netdev,
			"%s: Failed to register netdev for %s, err = 0x%08x\n",
			__func__, netdev->name, (int)err);
		err = -ENODEV;
		goto ez_net_probe_error;
	}
	return 0;

ez_net_probe_error:
	free_netdev(netdev);
	return err;
}

static int __devexit ez_net_remove(struct platform_device *pdev)
{
	struct net_device *netdev;
	EZ_NET_PRIV *netPriv;

	if (!pdev) {
		printk(KERN_ERR "%s: Can not remove device\n", __func__);
		return -EINVAL;
	}
	netdev = platform_get_drvdata(pdev);

	unregister_netdev(netdev);

	netPriv = netdev_priv(netdev);

	ez_net_hw_disable_control();

	free_irq(IRQ_LAN_RX_LINE, npsdev);
	free_irq(IRQ_LAN_TX_LINE, npsdev);


	free_netdev(netdev);

	return 0;
}

static struct platform_driver nps_lan_driver = {
	.probe = ez_net_probe,
	.remove = __devexit_p(ez_net_remove),
	.driver = {
		.owner = THIS_MODULE,
		.name = DRV_NAME,
	},
};

static int __init nps_enet_init_module(void)
{
	int rc;

	printk_init(KERN_INFO "%s", version);
	rc = platform_driver_register(&nps_lan_driver);
	if (rc) {
		printk(KERN_ERR "%s: Can not register device\n", __func__);
		return rc;
	}
	return 0;
}

static void __exit nps_enet_cleanup_module(void)
{
	platform_driver_unregister(&nps_lan_driver);
}

module_exit(nps_enet_cleanup_module);
module_init(nps_enet_init_module);

