/*
 * Stub implementation of libbwdpi.so for builds without BWDPI support
 * This provides minimal dummy implementations for prebuilt binaries
 * that have hard dependencies on libbwdpi.so
 */

#include <string.h>

/* Define bwdpi_device structure matching the real BWDPI API */
typedef struct bwdpi_client bwdpi_device;
struct bwdpi_client {
	char hostname[32];
	char vendor_name[100];
	char type_name[100];
	char device_name[100];
};

/*
 * Stub for bwdpi_client_info - called by networkmap to get device info
 * Returns -1 to indicate BWDPI is not available
 */
int bwdpi_client_info(char *MAC, char *ipaddr, bwdpi_device *device)
{
	/* Clear device info and return failure */
	if (device) {
		memset(device, 0, sizeof(bwdpi_device));
		device->hostname[0] = '\0';
		device->vendor_name[0] = '\0';
		device->type_name[0] = '\0';
		device->device_name[0] = '\0';
	}
	return -1;  /* Indicate BWDPI not available */
}
