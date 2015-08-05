/*
	Compile:
		clang -o callservicesd_hook.dylib -dynamiclib callservicesd_hook.m -framework Foundation
		
	Run:
		sudo osxinj callservicesd callservicesd_hook.dylib
*/

#import <objc/runtime.h>
#import <Foundation/Foundation.h>

@implementation NSXPCConnection(Overrides)
+(void)load {
   static dispatch_once_t token;
   dispatch_once(&token, ^{
      Class class = [self class];
      Method orig = class_getInstanceMethod(class, @selector(valueForEntitlement:));
      Method swiz = class_getInstanceMethod(class, @selector(my_valueForEntitlement:));
      method_exchangeImplementations(orig,swiz);
      NSLog(@“entitlement checks bypassed");
   });
}

-(id)my_valueForEntitlement:(id)arg1 { return @1; }
@end

