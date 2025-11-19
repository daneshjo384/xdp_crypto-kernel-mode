#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/crypto.h>

#define CRYPTO_KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16

static struct crypto_aead* aead_tfm;
static const u8 static_key[CRYPTO_KEY_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

// Encrypt a packet
static int encrypt_skb(struct sk_buff* skb) {
    struct scatterlist sg;
    struct aead_request* req;
    char iv[IV_SIZE];
    int err;

    req = aead_request_alloc(aead_tfm, GFP_ATOMIC);
    if (!req)
        return -ENOMEM;

    // Production IV
    get_random_bytes(iv, IV_SIZE);

    sg_init_one(&sg, skb->data, skb->len);

    aead_request_set_tfm(req, aead_tfm);
    aead_request_set_ad(req, 0);
    aead_request_set_crypt(req, &sg, &sg, skb->len, iv);

    err = crypto_aead_encrypt(req);
    aead_request_free(req);

    return err;
}

// Create a Hook in the bottom layer
static struct packet_type crypto_packet_type __read_mostly = {
    .type = htons(ETH_P_IP),
    .func = encrypt_skb,
};

static int __init crypto_xdp_init(void) {
    int err;

    aead_tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(aead_tfm)) {
        printk(KERN_ERR "Failed to allocate AEAD handle\n");
        return PTR_ERR(aead_tfm);
    }

    err = crypto_aead_setkey(aead_tfm, static_key, CRYPTO_KEY_SIZE);
    if (err) {
        printk(KERN_ERR "Failed to set key\n");
        crypto_free_aead(aead_tfm);
        return err;
    }

    dev_add_pack(&crypto_packet_type);

    printk(KERN_INFO "Crypto XDP Kernel Module Loaded\n");
    return 0;
}

static void __exit crypto_xdp_exit(void) {
    dev_remove_pack(&crypto_packet_type);
    crypto_free_aead(aead_tfm);
    printk(KERN_INFO "Crypto XDP Kernel Module Removed\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Physical Layer Crypto with XDP and Crypto API");

module_init(crypto_xdp_init);
module_exit(crypto_xdp_exit);