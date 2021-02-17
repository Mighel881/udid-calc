#import <Foundation/Foundation.h>
#if !(__arm64e__)
#import <CommonCrypto/CommonDigest.h>
#endif

NSString *getUDID() {

    // Please note, this will not ensure the UDID you get is untampered with!
    // This is simply a way to calculate it manually, and using this over the one liner
    // does not mean it's more secure. It is just an alternative way.

    // All of this below is equivalent to the one line:
    // NSString *UDID = (NSString *)CFBridgingRelease((CFStringRef)MGCopyAnswer(CFSTR("UniqueDeviceID")));

    #if __arm64e__

    // All we need for A12 is Chip ID and ECID
    NSNumber *chipIDNumber = (NSNumber*)CFBridgingRelease((CFStringRef)MGCopyAnswer(CFSTR("ChipID")));
    NSNumber *ecidNumber = (NSNumber*)CFBridgingRelease((CFStringRef)MGCopyAnswer(CFSTR("UniqueChipID")));
    NSString *chipid = [chipIDNumber stringValue];
    NSString *ecid = [ecidNumber stringValue];

    // Format should be 8 characters of Chip ID, left padded with 0s...
    for(int i = 0; i < 8 - chipid.length; i ++) {
        chipid = [NSString stringWithFormat:@"0%@", chipid];
    }

    // And then 16 characters of ECID left padded with 0s
    for(int i = 0; i < 16 - ecid.length; i ++) {
        ecid = [NSString stringWithFormat:@"0%@", ecid];
    }

    // A hyphen is placed in the middle
    NSString *secret = [NSString stringWithFormat:@"%@-%@", chipid, ecid];

    #else

    // A11 and lower UDID = SHA1(serial + ecid + wifiAddress + bluetoothAddress)
    NSString *serial = (NSString *)CFBridgingRelease((CFStringRef)MGCopyAnswer(CFSTR("SerialNumber")));
    NSString *ecid = (NSString *)CFBridgingRelease((CFStringRef)MGCopyAnswer(CFSTR("UniqueChipID")));
    NSString *wifiAddress = (NSString *)CFBridgingRelease((CFStringRef)MGCopyAnswer(CFSTR("WifiAddress")));
    NSString *bluetoothAddress = (NSString *)CFBridgingRelease((CFStringRef)MGCopyAnswer(CFSTR("BluetoothAddress")));

    // Combine them
    NSString *combined = [NSString stringWithFormat:@"%@%@%@%@", serial, ecid, wifiAddress, bluetoothAddress];

    // Get our SHA1. This is why we need Security framework
    NSData *data = [combined dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);

    NSMutableString *secret = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];

    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [secret appendFormat:@"%02x", digest[i]];
    }

    #endif

    // Send what we got.
    return secret;

}

int main() {
    NSLog(@"UDID: %@", getUDID());
    return 0;
}
