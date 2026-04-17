/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <jni.h>
#include <android/log.h>
#include <android/multinetwork.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct go_string { const char *str; long n; };
extern int wgTurnOn(struct go_string ifname, int tun_fd, struct go_string settings);
extern void wgTurnOff(int handle);
extern int wgGetSocketV4(int handle);
extern int wgGetSocketV6(int handle);
extern char *wgGetConfig(int handle);
extern char *wgVersion();
extern int wgTurnProxyStart(const char *peer_addr, const char *vklink, const char *mode, int n, int udp, const char *listen_addr, const char *turn_ip, int turn_port, const char *peer_type, int streams_per_cred, int watchdog_timeout, const char *vk_credentials_profile, int stream_start_delay_ms, int startup_timeout_sec, int quota_backoff_sec, long long network_handle, const char *public_key, int keepalive_sec);
extern void wgTurnProxyStop();
extern void wgNotifyNetworkChange();
extern char *wgTurnProxyGetRuntimeStatusJson();

static JavaVM *java_vm;
static jobject vpn_service_global;
static jobject app_context_global;
static jmethodID protect_method;
static jmethodID get_system_service_method;
static jmethodID get_all_networks_method;
static jmethodID get_active_network_method;
static jmethodID get_network_handle_method;
static jmethodID get_network_capabilities_method;
static jmethodID get_link_properties_method;
static jmethodID has_transport_method;
static jmethodID has_capability_method;
static jmethodID bind_socket_method;
static jmethodID get_all_by_name_method;
static jmethodID get_dns_servers_method;
static jmethodID list_size_method;
static jmethodID list_get_method;
static jmethodID inet_get_host_address_method;
static jfieldID file_descriptor_descriptor;
static jmethodID file_descriptor_init;
static jclass connectivity_manager_class_global;
static jclass network_class_global;
static jclass network_capabilities_class_global;
static jclass file_descriptor_class_global;
static jclass link_properties_class_global;
static jclass list_class_global;
static jclass inet_address_class_global;
static jclass turn_backend_class_global;
static jobject connectivity_manager_instance_global;
static jobject current_network_global = NULL;
static jlong current_network_handle = 0;
static char current_dns_csv[512] = {0};
static jmethodID fetch_url_on_current_network_method;
static jmethodID post_url_on_current_network_method;
static jmethodID on_captcha_required_method;
static int kernel_mode_socket_routing = 0;

static int clear_pending_exception(JNIEnv *env, const char *where)
{
	if (!(*env)->ExceptionCheck(env))
		return 0;
	__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI", "%s: clearing pending JNI exception", where);
	(*env)->ExceptionClear(env);
	return -1;
}

static void refresh_current_dns_servers(JNIEnv *env)
{
	current_dns_csv[0] = '\0';
	if (!connectivity_manager_instance_global || !current_network_global || !get_link_properties_method || !get_dns_servers_method ||
		!list_size_method || !list_get_method || !inet_get_host_address_method)
		return;

	jobject lp = (*env)->CallObjectMethod(env, connectivity_manager_instance_global, get_link_properties_method, current_network_global);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		return;
	}
	if (!lp)
		return;

	jobject dns_list = (*env)->CallObjectMethod(env, lp, get_dns_servers_method);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		(*env)->DeleteLocalRef(env, lp);
		return;
	}
	if (!dns_list) {
		(*env)->DeleteLocalRef(env, lp);
		return;
	}

	jint size = (*env)->CallIntMethod(env, dns_list, list_size_method);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		(*env)->DeleteLocalRef(env, dns_list);
		(*env)->DeleteLocalRef(env, lp);
		return;
	}

	size_t off = 0;
	for (jint i = 0; i < size; i++) {
		jobject inet = (*env)->CallObjectMethod(env, dns_list, list_get_method, i);
		if ((*env)->ExceptionCheck(env)) {
			(*env)->ExceptionClear(env);
			break;
		}
		if (!inet)
			continue;
		jstring host = (jstring)(*env)->CallObjectMethod(env, inet, inet_get_host_address_method);
		if ((*env)->ExceptionCheck(env)) {
			(*env)->ExceptionClear(env);
			(*env)->DeleteLocalRef(env, inet);
			continue;
		}
		if (host) {
			const char *host_str = (*env)->GetStringUTFChars(env, host, NULL);
			if (host_str) {
				size_t host_len = strlen(host_str);
				if (host_len > 0 && off + host_len + 2 < sizeof(current_dns_csv)) {
					if (off > 0)
						current_dns_csv[off++] = ',';
					memcpy(current_dns_csv + off, host_str, host_len);
					off += host_len;
					current_dns_csv[off] = '\0';
				}
				(*env)->ReleaseStringUTFChars(env, host, host_str);
			}
			(*env)->DeleteLocalRef(env, host);
		}
		(*env)->DeleteLocalRef(env, inet);
	}

	(*env)->DeleteLocalRef(env, dns_list);
	(*env)->DeleteLocalRef(env, lp);
}

static void ensure_connectivity_manager(JNIEnv *env, jobject context_obj)
{
	if (connectivity_manager_instance_global || !context_obj)
		return;

	if (!connectivity_manager_class_global) {
		jclass cm_class = (*env)->FindClass(env, "android/net/ConnectivityManager");
		if (!cm_class) {
			if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
			return;
		}
		connectivity_manager_class_global = (*env)->NewGlobalRef(env, cm_class);
		(*env)->DeleteLocalRef(env, cm_class);
		get_all_networks_method = (*env)->GetMethodID(env, connectivity_manager_class_global, "getAllNetworks", "()[Landroid/net/Network;");
		get_active_network_method = (*env)->GetMethodID(env, connectivity_manager_class_global, "getActiveNetwork", "()Landroid/net/Network;");
		get_network_capabilities_method = (*env)->GetMethodID(env, connectivity_manager_class_global, "getNetworkCapabilities", "(Landroid/net/Network;)Landroid/net/NetworkCapabilities;");
		get_link_properties_method = (*env)->GetMethodID(env, connectivity_manager_class_global, "getLinkProperties", "(Landroid/net/Network;)Landroid/net/LinkProperties;");
		clear_pending_exception(env, "ConnectivityManager method lookup");
	}
	if (!network_class_global) {
		jclass n_class = (*env)->FindClass(env, "android/net/Network");
		if (!n_class) {
			if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
			return;
		}
		network_class_global = (*env)->NewGlobalRef(env, n_class);
		(*env)->DeleteLocalRef(env, n_class);
		get_network_handle_method = (*env)->GetMethodID(env, network_class_global, "getNetworkHandle", "()J");
		bind_socket_method = (*env)->GetMethodID(env, network_class_global, "bindSocket", "(Ljava/io/FileDescriptor;)V");
		get_all_by_name_method = (*env)->GetMethodID(env, network_class_global, "getAllByName", "(Ljava/lang/String;)[Ljava/net/InetAddress;");
		clear_pending_exception(env, "Network method lookup");
	}
	if (!network_capabilities_class_global) {
		jclass nc_class = (*env)->FindClass(env, "android/net/NetworkCapabilities");
		if (!nc_class) {
			if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
			return;
		}
		network_capabilities_class_global = (*env)->NewGlobalRef(env, nc_class);
		(*env)->DeleteLocalRef(env, nc_class);
		has_transport_method = (*env)->GetMethodID(env, network_capabilities_class_global, "hasTransport", "(I)Z");
		has_capability_method = (*env)->GetMethodID(env, network_capabilities_class_global, "hasCapability", "(I)Z");
		clear_pending_exception(env, "NetworkCapabilities method lookup");
	}
	if (!link_properties_class_global) {
		jclass lp_class = (*env)->FindClass(env, "android/net/LinkProperties");
		if (!lp_class) {
			if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
			return;
		}
		link_properties_class_global = (*env)->NewGlobalRef(env, lp_class);
		(*env)->DeleteLocalRef(env, lp_class);
		get_dns_servers_method = (*env)->GetMethodID(env, link_properties_class_global, "getDnsServers", "()Ljava/util/List;");
		clear_pending_exception(env, "LinkProperties method lookup");
	}
	if (!list_class_global) {
		jclass l_class = (*env)->FindClass(env, "java/util/List");
		if (!l_class) {
			if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
			return;
		}
		list_class_global = (*env)->NewGlobalRef(env, l_class);
		(*env)->DeleteLocalRef(env, l_class);
		list_size_method = (*env)->GetMethodID(env, list_class_global, "size", "()I");
		list_get_method = (*env)->GetMethodID(env, list_class_global, "get", "(I)Ljava/lang/Object;");
		clear_pending_exception(env, "List method lookup");
	}
	if (!inet_address_class_global) {
		jclass ia_class = (*env)->FindClass(env, "java/net/InetAddress");
		if (!ia_class) {
			if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
			return;
		}
		inet_address_class_global = (*env)->NewGlobalRef(env, ia_class);
		(*env)->DeleteLocalRef(env, ia_class);
		inet_get_host_address_method = (*env)->GetMethodID(env, inet_address_class_global, "getHostAddress", "()Ljava/lang/String;");
		clear_pending_exception(env, "InetAddress method lookup");
	}
	if (!turn_backend_class_global) {
		jclass tb_class = (*env)->FindClass(env, "com/wireguard/android/backend/TurnBackend");
		if (!tb_class) {
			if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
			return;
		}
		turn_backend_class_global = (*env)->NewGlobalRef(env, tb_class);
		(*env)->DeleteLocalRef(env, tb_class);
		fetch_url_on_current_network_method = (*env)->GetStaticMethodID(env, turn_backend_class_global, "fetchUrlOnCurrentNetwork", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
		post_url_on_current_network_method = (*env)->GetStaticMethodID(env, turn_backend_class_global, "postUrlOnCurrentNetwork", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
		on_captcha_required_method = (*env)->GetStaticMethodID(env, turn_backend_class_global, "onCaptchaRequired", "(ILjava/lang/String;)Ljava/lang/String;");
		clear_pending_exception(env, "TurnBackend method lookup");
	}
	if (!file_descriptor_class_global) {
		jclass fd_class = (*env)->FindClass(env, "java/io/FileDescriptor");
		if (!fd_class) {
			if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
			return;
		}
		file_descriptor_class_global = (*env)->NewGlobalRef(env, fd_class);
		(*env)->DeleteLocalRef(env, fd_class);
		file_descriptor_init = (*env)->GetMethodID(env, file_descriptor_class_global, "<init>", "()V");
		file_descriptor_descriptor = (*env)->GetFieldID(env, file_descriptor_class_global, "descriptor", "I");
		if (clear_pending_exception(env, "FileDescriptor lookup") != 0) {
			file_descriptor_init = NULL;
			file_descriptor_descriptor = NULL;
		}
	}

	jclass context_class = (*env)->GetObjectClass(env, context_obj);
	jmethodID context_get_system_service = (*env)->GetMethodID(env, context_class, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
	if (!context_get_system_service) {
		if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
		(*env)->DeleteLocalRef(env, context_class);
		return;
	}
	jstring cm_service_name = (*env)->NewStringUTF(env, "connectivity");
	jobject cm_obj = (*env)->CallObjectMethod(env, context_obj, context_get_system_service, cm_service_name);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
	} else if (cm_obj) {
		connectivity_manager_instance_global = (*env)->NewGlobalRef(env, cm_obj);
		(*env)->DeleteLocalRef(env, cm_obj);
	}
	(*env)->DeleteLocalRef(env, cm_service_name);
	(*env)->DeleteLocalRef(env, context_class);
}

static jobject select_best_network(JNIEnv *env)
{
	if (!connectivity_manager_instance_global)
		return NULL;

	if (get_network_capabilities_method && has_transport_method && has_capability_method && get_all_networks_method) {
		jobjectArray networks = (jobjectArray)(*env)->CallObjectMethod(env, connectivity_manager_instance_global, get_all_networks_method);
		if (networks) {
			jsize len = (*env)->GetArrayLength(env, networks);
			for (jsize i = 0; i < len; i++) {
				jobject network_obj = (*env)->GetObjectArrayElement(env, networks, i);
				if (!network_obj) {
					continue;
				}
				jobject caps = (*env)->CallObjectMethod(env, connectivity_manager_instance_global, get_network_capabilities_method, network_obj);
				if (caps) {
					jboolean has_internet = (*env)->CallBooleanMethod(env, caps, has_capability_method, 12 /* NET_CAPABILITY_INTERNET */);
					jboolean is_vpn = (*env)->CallBooleanMethod(env, caps, has_transport_method, 4 /* TRANSPORT_VPN */);
					if (has_internet && !is_vpn) {
						jobject ret = (*env)->NewGlobalRef(env, network_obj);
						(*env)->DeleteLocalRef(env, caps);
						(*env)->DeleteLocalRef(env, network_obj);
						(*env)->DeleteLocalRef(env, networks);
						return ret;
					}
					(*env)->DeleteLocalRef(env, caps);
				}
				(*env)->DeleteLocalRef(env, network_obj);
			}
			(*env)->DeleteLocalRef(env, networks);
		}
		if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
	}

	if (get_active_network_method) {
		jobject active = (*env)->CallObjectMethod(env, connectivity_manager_instance_global, get_active_network_method);
		if (active) {
			jobject ret = (*env)->NewGlobalRef(env, active);
			(*env)->DeleteLocalRef(env, active);
			if (ret)
				return ret;
		}
		if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
	}

	return NULL;
}

// Helper to update the cached Network object
static void update_current_network(JNIEnv *env, jlong handle)
{
	if (current_network_global) {
		(*env)->DeleteGlobalRef(env, current_network_global);
		current_network_global = NULL;
	}
	current_network_handle = handle;

	if (!connectivity_manager_instance_global)
		return;

	if (handle != 0 && get_all_networks_method && get_network_handle_method) {
		jobjectArray networks = (jobjectArray)(*env)->CallObjectMethod(env, connectivity_manager_instance_global, get_all_networks_method);
		if (networks) {
			jsize len = (*env)->GetArrayLength(env, networks);
			for (jsize i = 0; i < len; i++) {
				jobject network_obj = (*env)->GetObjectArrayElement(env, networks, i);
				if (network_obj && handle == (*env)->CallLongMethod(env, network_obj, get_network_handle_method)) {
					current_network_global = (*env)->NewGlobalRef(env, network_obj);
					(*env)->DeleteLocalRef(env, network_obj);
					break;
				}
				if (network_obj)
					(*env)->DeleteLocalRef(env, network_obj);
			}
			(*env)->DeleteLocalRef(env, networks);
		}
		if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
	}

	if (!current_network_global) {
		current_network_global = select_best_network(env);
		if (current_network_global) {
			__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI",
				"update_current_network: fallback network selected for handle=%lld", (long long)handle);
		} else {
			__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI", "update_current_network: FAILED - network not found for handle=%lld", (long long)handle);
		}
	} else {
		__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI", "update_current_network: matched handle=%lld", (long long)handle);
	}
	refresh_current_dns_servers(env);
	if (current_dns_csv[0] != '\0') {
		__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI", "current network DNS: %s", current_dns_csv);
	}
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	java_vm = vm;
	return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgSetVpnService(JNIEnv *env, jclass c, jobject vpn_service)
{
	if (vpn_service_global) {
		(*env)->DeleteGlobalRef(env, vpn_service_global);
		vpn_service_global = NULL;
		protect_method = NULL;
		get_system_service_method = NULL;
	}
	if (vpn_service) {
		vpn_service_global = (*env)->NewGlobalRef(env, vpn_service);
		jclass vpn_service_class = (*env)->GetObjectClass(env, vpn_service_global);
		protect_method = (*env)->GetMethodID(env, vpn_service_class, "protect", "(I)Z");
		get_system_service_method = (*env)->GetMethodID(env, vpn_service_class, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
		ensure_connectivity_manager(env, vpn_service_global);
	}
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgSetApplicationContext(JNIEnv *env, jclass c, jobject context)
{
	if (app_context_global) {
		(*env)->DeleteGlobalRef(env, app_context_global);
		app_context_global = NULL;
	}
	if (!context)
		return;
	app_context_global = (*env)->NewGlobalRef(env, context);
	ensure_connectivity_manager(env, app_context_global);
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgSetKernelModeSocketRouting(JNIEnv *env, jclass c, jboolean enabled)
{
	(void)env;
	(void)c;
	kernel_mode_socket_routing = enabled ? 1 : 0;
	__android_log_print(
		ANDROID_LOG_INFO,
		"WireGuard/JNI",
		"wgSetKernelModeSocketRouting: %s",
		kernel_mode_socket_routing ? "kernel-direct" : "vpn-service"
	);
}

static int bind_socket_to_current_network(JNIEnv *env, int fd)
{
	if (!current_network_global || !bind_socket_method || !file_descriptor_class_global || !file_descriptor_init || !file_descriptor_descriptor)
		return -1;

	jobject fd_obj = (*env)->NewObject(env, file_descriptor_class_global, file_descriptor_init);
	if (!fd_obj) {
		if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
		return -1;
	}
	(*env)->SetIntField(env, fd_obj, file_descriptor_descriptor, fd);
	(*env)->CallVoidMethod(env, current_network_global, bind_socket_method, fd_obj);
	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI", "bind_socket_to_current_network: bindSocket threw for fd=%d handle=%lld, describing exception", fd, (long long)current_network_handle);
		(*env)->ExceptionDescribe(env);
		(*env)->ExceptionClear(env);
		(*env)->DeleteLocalRef(env, fd_obj);
		return -1;
	}
	(*env)->DeleteLocalRef(env, fd_obj);
	return 0;
}

static int bind_socket_to_network_handle(int fd)
{
	if (current_network_handle == 0)
		return -1;
	return android_setsocknetwork((net_handle_t)current_network_handle, fd);
}

int wgProtectSocket(int fd)
{
	JNIEnv *env;
	int attached = 0;
	int ret = -1;

	// Validate fd
	if (fd < 0) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"wgProtectSocket: invalid fd=%d", fd);
		return -1;
	}

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"wgProtectSocket(fd=%d): AttachCurrentThread failed", fd);
			return -1;
		}
		attached = 1;
	}

	if (kernel_mode_socket_routing) {
		if (bind_socket_to_network_handle(fd) == 0) {
			__android_log_print(
				ANDROID_LOG_INFO,
				"WireGuard/JNI",
				"wgProtectSocket(fd=%d): kernel-direct mode bound to handle=%lld via android_setsocknetwork",
				fd,
				(long long)current_network_handle
			);
			ret = 0;
		} else {
			__android_log_print(
				ANDROID_LOG_WARN,
				"WireGuard/JNI",
				"wgProtectSocket(fd=%d): kernel-direct android_setsocknetwork failed for handle=%lld, leaving system routing unchanged",
				fd,
				(long long)current_network_handle
			);
			ret = 0;
		}
		goto out;
	}

	// Kernel/root backend without VpnService fallback.
	if (!vpn_service_global || !protect_method) {
		ensure_connectivity_manager(env, app_context_global);
		if (bind_socket_to_current_network(env, fd) == 0) {
			__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI", "wgProtectSocket(fd=%d): SUCCESS (bound-only, no VpnService, handle=%lld)", fd, (long long)current_network_handle);
			ret = 0;
		} else {
			/*
			 * In root/kernel backend there is no VpnService tunnel to protect against.
			 * Binding improves path selection, but failing to bind must not block sockets entirely.
			 */
			__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI", "wgProtectSocket(fd=%d): bind failed without VpnService, continuing unbound (handle=%lld)", fd, (long long)current_network_handle);
			ret = 0;
		}
	} else {
		if ((*env)->CallBooleanMethod(env, vpn_service_global, protect_method, (jint)fd)) {
			if (bind_socket_to_current_network(env, fd) == 0) {
				__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI", "wgProtectSocket(fd=%d): SUCCESS (protected + bound to net %lld)", fd, (long long)current_network_handle);
			} else {
				__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI", "wgProtectSocket(fd=%d): SUCCESS (protected, no bind, handle=%lld)", fd, (long long)current_network_handle);
			}
			ret = 0;
		} else {
			/*
			 * In root/kernel backend we can still reach a state where a stale/non-ready
			 * VpnService instance is visible from JNI while traffic must go via a physical
			 * non-VPN network. If protect() fails, try binding to the selected network
			 * instead of hard-failing the socket.
			 */
			__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI", "wgProtectSocket(fd=%d): VpnService.protect() FAILED, trying bind-only fallback", fd);
			ensure_connectivity_manager(env, app_context_global);
			if (bind_socket_to_current_network(env, fd) == 0) {
				__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI", "wgProtectSocket(fd=%d): SUCCESS (bind-only fallback, handle=%lld)", fd, (long long)current_network_handle);
				ret = 0;
			} else {
				__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI", "wgProtectSocket(fd=%d): protect failed and bind fallback failed", fd);
				ret = -1;
			}
		}
	}
out:
	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
	return ret;
}

char *wgResolveWithCurrentNetwork(const char *hostname)
{
	JNIEnv *env;
	int attached = 0;
	char *result = NULL;

	if (!hostname || !hostname[0])
		return NULL;

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"wgResolveWithCurrentNetwork(%s): AttachCurrentThread failed", hostname);
			return NULL;
		}
		attached = 1;
	}

	if (kernel_mode_socket_routing) {
		__android_log_print(
			ANDROID_LOG_INFO,
			"WireGuard/JNI",
			"wgResolveWithCurrentNetwork(%s): skipped in kernel-direct mode",
			hostname
		);
		goto out;
	}

	ensure_connectivity_manager(env, vpn_service_global ? vpn_service_global : app_context_global);
	if (!current_network_global || !get_all_by_name_method || !inet_get_host_address_method) {
		goto out;
	}

	jstring host = (*env)->NewStringUTF(env, hostname);
	if (!host) {
		if ((*env)->ExceptionCheck(env))
			(*env)->ExceptionClear(env);
		goto out;
	}

	jobjectArray inet_array = (jobjectArray)(*env)->CallObjectMethod(env, current_network_global, get_all_by_name_method, host);
	(*env)->DeleteLocalRef(env, host);
	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI",
			"wgResolveWithCurrentNetwork(%s): getAllByName threw, describing exception", hostname);
		(*env)->ExceptionDescribe(env);
		(*env)->ExceptionClear(env);
		goto out;
	}
	if (!inet_array)
		goto out;

	jsize len = (*env)->GetArrayLength(env, inet_array);
	for (jsize i = 0; i < len; i++) {
		jobject inet = (*env)->GetObjectArrayElement(env, inet_array, i);
		if (!inet)
			continue;
		jstring host_addr = (jstring)(*env)->CallObjectMethod(env, inet, inet_get_host_address_method);
		if ((*env)->ExceptionCheck(env)) {
			(*env)->ExceptionClear(env);
			(*env)->DeleteLocalRef(env, inet);
			continue;
		}
		if (host_addr) {
			const char *host_addr_str = (*env)->GetStringUTFChars(env, host_addr, NULL);
			if (host_addr_str && host_addr_str[0]) {
				if (!strchr(host_addr_str, ':')) {
					result = strdup(host_addr_str);
					(*env)->ReleaseStringUTFChars(env, host_addr, host_addr_str);
					(*env)->DeleteLocalRef(env, host_addr);
					(*env)->DeleteLocalRef(env, inet);
					break;
				}
				if (!result)
					result = strdup(host_addr_str);
				(*env)->ReleaseStringUTFChars(env, host_addr, host_addr_str);
			}
			(*env)->DeleteLocalRef(env, host_addr);
		}
		(*env)->DeleteLocalRef(env, inet);
	}
	(*env)->DeleteLocalRef(env, inet_array);

out:
	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
	return result;
}

char *wgResolveAllWithCurrentNetwork(const char *hostname)
{
	JNIEnv *env;
	int attached = 0;
	char *result = NULL;

	if (!hostname || !hostname[0])
		return NULL;

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"wgResolveAllWithCurrentNetwork(%s): AttachCurrentThread failed", hostname);
			return NULL;
		}
		attached = 1;
	}

	if (kernel_mode_socket_routing) {
		__android_log_print(
			ANDROID_LOG_INFO,
			"WireGuard/JNI",
			"wgResolveAllWithCurrentNetwork(%s): skipped in kernel-direct mode",
			hostname
		);
		goto out;
	}

	ensure_connectivity_manager(env, vpn_service_global ? vpn_service_global : app_context_global);
	if (!current_network_global || !get_all_by_name_method || !inet_get_host_address_method) {
		goto out;
	}

	jstring host = (*env)->NewStringUTF(env, hostname);
	if (!host) {
		if ((*env)->ExceptionCheck(env))
			(*env)->ExceptionClear(env);
		goto out;
	}

	jobjectArray inet_array = (jobjectArray)(*env)->CallObjectMethod(env, current_network_global, get_all_by_name_method, host);
	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI",
			"wgResolveAllWithCurrentNetwork(%s): getAllByName threw, refreshing current network and retrying once", hostname);
		(*env)->ExceptionDescribe(env);
		(*env)->ExceptionClear(env);
		update_current_network(env, current_network_handle);
		if (current_network_global) {
			inet_array = (jobjectArray)(*env)->CallObjectMethod(env, current_network_global, get_all_by_name_method, host);
			if ((*env)->ExceptionCheck(env)) {
				__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI",
					"wgResolveAllWithCurrentNetwork(%s): retry getAllByName threw", hostname);
				(*env)->ExceptionDescribe(env);
				(*env)->ExceptionClear(env);
				(*env)->DeleteLocalRef(env, host);
				goto out;
			}
		}
	}
	(*env)->DeleteLocalRef(env, host);
	if (!inet_array)
		goto out;

	jsize len = (*env)->GetArrayLength(env, inet_array);
	size_t total_len = 0;
	char *buffer = NULL;
	for (jsize i = 0; i < len; i++) {
		jobject inet = (*env)->GetObjectArrayElement(env, inet_array, i);
		if (!inet)
			continue;
		jstring host_addr = (jstring)(*env)->CallObjectMethod(env, inet, inet_get_host_address_method);
		if ((*env)->ExceptionCheck(env)) {
			(*env)->ExceptionClear(env);
			(*env)->DeleteLocalRef(env, inet);
			continue;
		}
		if (host_addr) {
			const char *host_addr_str = (*env)->GetStringUTFChars(env, host_addr, NULL);
			if (host_addr_str && host_addr_str[0] && !strchr(host_addr_str, ':')) {
				size_t part_len = strlen(host_addr_str);
				size_t new_len = total_len + part_len + (total_len > 0 ? 1 : 0) + 1;
				char *new_buffer = realloc(buffer, new_len);
				if (new_buffer) {
					buffer = new_buffer;
					if (total_len > 0)
						buffer[total_len++] = ',';
					memcpy(buffer + total_len, host_addr_str, part_len);
					total_len += part_len;
					buffer[total_len] = '\0';
				}
			}
			if (host_addr_str)
				(*env)->ReleaseStringUTFChars(env, host_addr, host_addr_str);
			(*env)->DeleteLocalRef(env, host_addr);
		}
		(*env)->DeleteLocalRef(env, inet);
	}
	(*env)->DeleteLocalRef(env, inet_array);
	result = buffer;

out:
	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
	return result;
}

char *wgFetchUrlWithCurrentNetwork(const char *raw_url, const char *user_agent)
{
	JNIEnv *env;
	int attached = 0;
	char *result = NULL;

	if (!raw_url || !raw_url[0])
		return NULL;

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"wgFetchUrlWithCurrentNetwork(%s): AttachCurrentThread failed", raw_url);
			return NULL;
		}
		attached = 1;
	}

	ensure_connectivity_manager(env, vpn_service_global ? vpn_service_global : app_context_global);
	if (!turn_backend_class_global || !fetch_url_on_current_network_method) {
		goto out;
	}

	jstring url = (*env)->NewStringUTF(env, raw_url);
	jstring ua = (*env)->NewStringUTF(env, user_agent ? user_agent : "");
	if (!url || !ua) {
		if ((*env)->ExceptionCheck(env))
			(*env)->ExceptionClear(env);
		goto out;
	}

	jstring body = (jstring)(*env)->CallStaticObjectMethod(env, turn_backend_class_global, fetch_url_on_current_network_method, url, ua);
	(*env)->DeleteLocalRef(env, url);
	(*env)->DeleteLocalRef(env, ua);
	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI",
			"wgFetchUrlWithCurrentNetwork(%s): Java fetch threw", raw_url);
		(*env)->ExceptionDescribe(env);
		(*env)->ExceptionClear(env);
		goto out;
	}
	if (body) {
		const char *body_str = (*env)->GetStringUTFChars(env, body, NULL);
		if (body_str && body_str[0]) {
			result = strdup(body_str);
			(*env)->ReleaseStringUTFChars(env, body, body_str);
		}
		(*env)->DeleteLocalRef(env, body);
	}

out:
	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
	return result;
}

char *wgPostUrlWithCurrentNetwork(const char *raw_url, const char *post_data, const char *user_agent)
{
	JNIEnv *env;
	int attached = 0;
	char *result = NULL;

	if (!raw_url || !raw_url[0])
		return NULL;

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"wgPostUrlWithCurrentNetwork(%s): AttachCurrentThread failed", raw_url);
			return NULL;
		}
		attached = 1;
	}

	ensure_connectivity_manager(env, vpn_service_global ? vpn_service_global : app_context_global);
	if (!turn_backend_class_global || !post_url_on_current_network_method) {
		goto out;
	}

	jstring url = (*env)->NewStringUTF(env, raw_url);
	jstring data = (*env)->NewStringUTF(env, post_data ? post_data : "");
	jstring ua = (*env)->NewStringUTF(env, user_agent ? user_agent : "");
	if (!url || !data || !ua) {
		if ((*env)->ExceptionCheck(env))
			(*env)->ExceptionClear(env);
		goto out;
	}

	jstring body = (jstring)(*env)->CallStaticObjectMethod(env, turn_backend_class_global, post_url_on_current_network_method, url, data, ua);
	(*env)->DeleteLocalRef(env, url);
	(*env)->DeleteLocalRef(env, data);
	(*env)->DeleteLocalRef(env, ua);
	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI",
			"wgPostUrlWithCurrentNetwork(%s): Java post threw", raw_url);
		(*env)->ExceptionDescribe(env);
		(*env)->ExceptionClear(env);
		goto out;
	}
	if (body) {
		const char *body_str = (*env)->GetStringUTFChars(env, body, NULL);
		if (body_str && body_str[0]) {
			result = strdup(body_str);
			(*env)->ReleaseStringUTFChars(env, body, body_str);
		}
		(*env)->DeleteLocalRef(env, body);
	}

out:
	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
	return result;
}

const char *wgGetCurrentDnsCsv(void)
{
	return current_dns_csv;
}

const char *getNetworkDnsServers(long long network_handle)
{
	(void)network_handle;
	return current_dns_csv[0] ? current_dns_csv : NULL;
}

const char *requestCaptcha(int cache_id, const char *redirect_uri)
{
	JNIEnv *env;
	int attached = 0;
	char *result = NULL;

	if (!redirect_uri || !turn_backend_class_global || !on_captcha_required_method) {
		__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI",
			"requestCaptcha unavailable (uri=%p class=%p method=%p)",
			redirect_uri, turn_backend_class_global, on_captcha_required_method);
		return NULL;
	}

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			return NULL;
		}
		attached = 1;
	}

	jstring uri = (*env)->NewStringUTF(env, redirect_uri);
	jstring token = (jstring)(*env)->CallStaticObjectMethod(env, turn_backend_class_global, on_captcha_required_method, (jint)cache_id, uri);
	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI", "requestCaptcha: Java callback threw");
		(*env)->ExceptionClear(env);
		token = NULL;
	}
	if (token) {
		const char *token_str = (*env)->GetStringUTFChars(env, token, NULL);
		if (token_str && token_str[0]) {
			result = strdup(token_str);
		}
		if (token_str) {
			(*env)->ReleaseStringUTFChars(env, token, token_str);
		}
		(*env)->DeleteLocalRef(env, token);
	}
	(*env)->DeleteLocalRef(env, uri);

	if (attached) {
		(*java_vm)->DetachCurrentThread(java_vm);
	}
	return result;
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
	const char *ifname_str = (*env)->GetStringUTFChars(env, ifname, 0);
	size_t ifname_len = (*env)->GetStringUTFLength(env, ifname);
	const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
	size_t settings_len = (*env)->GetStringUTFLength(env, settings);
	int ret = wgTurnOn((struct go_string){
		.str = ifname_str,
		.n = ifname_len
	}, tun_fd, (struct go_string){
		.str = settings_str,
		.n = settings_len
	});
	(*env)->ReleaseStringUTFChars(env, ifname, ifname_str);
	(*env)->ReleaseStringUTFChars(env, settings, settings_str);
	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
	wgTurnOff(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetConfig(JNIEnv *env, jclass c, jint handle)
{
	jstring ret;
	char *config = wgGetConfig(handle);
	if (!config)
		return NULL;
	ret = (*env)->NewStringUTF(env, config);
	free(config);
	return ret;
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgVersion(JNIEnv *env, jclass c)
{
	jstring ret;
	char *version = wgVersion();
	if (!version)
		return NULL;
	ret = (*env)->NewStringUTF(env, version);
	free(version);
	return ret;
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnProxyStart(JNIEnv *env, jclass c, jstring peer_addr, jstring vklink, jstring mode, jint n, jint useUdp, jstring listen_addr, jstring turn_ip, jint turn_port, jstring peer_type, jint streams_per_cred, jint watchdog_timeout, jstring vk_credentials_profile, jint stream_start_delay_ms, jint startup_timeout_sec, jint quota_backoff_sec, jlong network_handle, jstring public_key, jint keepalive_sec)
{
	const char *peer_addr_str = (*env)->GetStringUTFChars(env, peer_addr, 0);
	const char *vklink_str = (*env)->GetStringUTFChars(env, vklink, 0);
	const char *mode_str = (*env)->GetStringUTFChars(env, mode, 0);
	const char *listen_addr_str = (*env)->GetStringUTFChars(env, listen_addr, 0);
	const char *turn_ip_str = (*env)->GetStringUTFChars(env, turn_ip, 0);
	const char *peer_type_str = (*env)->GetStringUTFChars(env, peer_type, 0);
	const char *vk_credentials_profile_str = (*env)->GetStringUTFChars(env, vk_credentials_profile, 0);
	const char *public_key_str = (*env)->GetStringUTFChars(env, public_key, 0);

	update_current_network(env, network_handle);

	int ret = wgTurnProxyStart(peer_addr_str, vklink_str, mode_str, (int)n, (int)useUdp, listen_addr_str, turn_ip_str, (int)turn_port, peer_type_str, (int)streams_per_cred, (int)watchdog_timeout, vk_credentials_profile_str, (int)stream_start_delay_ms, (int)startup_timeout_sec, (int)quota_backoff_sec, (long long)network_handle, public_key_str, (int)keepalive_sec);
	(*env)->ReleaseStringUTFChars(env, peer_addr, peer_addr_str);
	(*env)->ReleaseStringUTFChars(env, vklink, vklink_str);
	(*env)->ReleaseStringUTFChars(env, mode, mode_str);
	(*env)->ReleaseStringUTFChars(env, listen_addr, listen_addr_str);
	(*env)->ReleaseStringUTFChars(env, turn_ip, turn_ip_str);
	(*env)->ReleaseStringUTFChars(env, peer_type, peer_type_str);
	(*env)->ReleaseStringUTFChars(env, vk_credentials_profile, vk_credentials_profile_str);
	(*env)->ReleaseStringUTFChars(env, public_key, public_key_str);
	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgNotifyNetworkChange(JNIEnv *env, jclass c)
{
	wgNotifyNetworkChange();
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnProxyStop(JNIEnv *env, jclass c)
{
	update_current_network(env, 0);
	wgTurnProxyStop();
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnProxyGetRuntimeStatusJson(JNIEnv *env, jclass c)
{
	char *status = wgTurnProxyGetRuntimeStatusJson();
	if (!status)
		return NULL;
	jstring ret = (*env)->NewStringUTF(env, status);
	free(status);
	return ret;
}
