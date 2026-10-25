/* SPDX-License-Identifier: MIT */
#import <AppKit/AppKit.h>

int lw_native_message_box(const char *text, const char *title)
{
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        [NSApp activateIgnoringOtherApps:YES];
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = [NSString stringWithUTF8String:title] ?: @"";
        alert.informativeText = [NSString stringWithUTF8String:text] ?: @"";
        [alert addButtonWithTitle:@"确定"];
        return [alert runModal] == NSAlertFirstButtonReturn ? 1 : 0;
    }
}
