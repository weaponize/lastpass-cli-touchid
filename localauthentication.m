//
//  localauthentication.m
//  Todd Manning 
//

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <stdio.h>

typedef enum {
    kTouchIDResultAllowed,
    kTouchIDResultNone,
    kTouchIDResultFailed
} TouchIDResult;


int localauthentication() {
    @autoreleasepool {
        LAContext *myContext = [[LAContext alloc] init];
        NSString *myLocalizedReasonString = @"access LastPass password";

        __block NSError *authError = nil;
        __block TouchIDResult result = kTouchIDResultNone;
        
        
        if ([myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError]) {
            // biometryType is only set after calling canEvaluatePolicy
            if (@available(macOS 10.13.2, *)) {
            
                // test for the types of biometry available on the current device
                // currently not using this, but the idea would be you could customize
                // based on how the user could locally authenticate
                switch(myContext.biometryType) {
                    case LABiometryTypeNone:
                        break;
                    case LABiometryTypeTouchID:
                        break;
                    // currently only iOS supports FaceID
                    case LABiometryTypeFaceID:
                        break;
                }

            } 

            [myContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                      localizedReason:myLocalizedReasonString
                                reply:^(BOOL success, NSError *error) {
                                    result = success ? kTouchIDResultAllowed : kTouchIDResultFailed;
                                    authError = error;
                                    CFRunLoopWakeUp(CFRunLoopGetCurrent());
                                }];
            
            while (result == kTouchIDResultNone) {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, true);
            }
            
            if (result == kTouchIDResultAllowed) {
                // printf("Biometric authentication succeeded\n");
            } else {
                // printf("Biometric authentication failed, errorcode==%ld userinfo=%s\n", (long)authError.code, [authError.localizedDescription UTF8String]);
            }
            
        } else {
            // Could not evaluate policy
            // printf("Could not perform biometric authentication...errorcode==%ld userinfo=%s\n", (long)authError.code, [authError.localizedDescription UTF8String]);
        }
        
        return (int)authError.code;

    }
}
