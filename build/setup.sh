echo 1 > /sys/module/msm_watchdog/parameters/runtime_disable

umount /sdcard
umount /datamedia
umount /cache
umount /ss
insmod ./msm_kexec.ko
insmod ./arm_kexec.ko
insmod ./kexec.ko
sleep 2
umount /firmware

./kexec -l ./zImage --atags --atags-file=./atags --image-size=33554432 --ramdisk=./ramdisk.gz --append="console=ttyHSL0,115200,n8 androidboot.hardware=qcom user_debug=31 msm_rtb.filter=0x3F ehci-hcd.park=3 sec_log=0x100000@0xffe00008 sec_dbg=0x80000@0xfff00008 sec_debug.reset_reason=0x1a2b3c00 lcd_attached=1 lcd_id=0x408047 androidboot.debug_level=0x4f4c sec_debug.enable=0 sec_debug.enable_user=0 androidboot.cp_debug_level=0x55FF sec_debug.enable_cp_debug=0 cordon=20086f51fdf06128e106a044568faecb connie=SCH-I545_VZW_USA_1055ee5b85eb4ce33e2512ae91cd7921 lpj=67678 loglevel=4 samsung.hardware=SCH-I545 androidboot.emmc_checksum=3 androidboot.bootloader=I545VRUEMJ7 androidboot.nvdata_backup=0 androidboot.boot_recovery=0 androidboot.check_recovery_condition=0x0 level=0x574f4c44 vmalloc=450m sec_pvs=0 batt_id_value=0 androidboot.csb_val=1 androidboot.emmc=true androidboot.serialno=8e22816d androidboot.baseband=mdm"
sleep 2
./kexec -e
