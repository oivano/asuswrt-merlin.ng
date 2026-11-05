int separate_tc_fw_from_trx(char *trxpath, long uploaded_len);
int stage_tc_firmware_from_trx(char *trxpath, long uploaded_len,
			       const char *stage_dir, int truncate_image);
int check_tc_firmware_stage(const char *stage_dir, int keep_image);
unsigned long crc32_no_comp(unsigned long crc,const unsigned char* buf, int len);
int check_tc_firmware_crc();
void do_upgrade_adsldrv();
int compare_linux_image(void);

