#import <Cocoa/Cocoa.h>
#include <iostream>
#include <string>

// A simple C++ function
std::string getGreeting() {
    return "Hello from C++!";
}

// AppDelegate Interface (Objective-C++)
@interface AppDelegate : NSObject <NSApplicationDelegate>
@end

// AppDelegate Implementation (Objective-C++)
@implementation AppDelegate
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    std::cout << getGreeting() << std::endl;  // Call the C++ function and print the greeting

    // Create a window programmatically
    NSRect frame = NSMakeRect(100, 100, 400, 300);
    NSUInteger style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable;
    NSWindow *window = [[NSWindow alloc] initWithContentRect:frame
                                                   styleMask:style
                                                     backing:NSBackingStoreBuffered
                                                       defer:NO];
    [window setTitle:@"Objective-C++ Window"];
    [window makeKeyAndOrderFront:nil];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return YES;
}
@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Create and run the application
        NSApplication *app = [NSApplication sharedApplication];
        AppDelegate *delegate = [[AppDelegate alloc] init];
        [app setDelegate:delegate];
        [app run];
    }
    return 0;
}
