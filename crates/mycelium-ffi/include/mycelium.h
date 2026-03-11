/**
 * Mycelium FFI C Header
 *
 * C-compatible API for the Mycelium mesh messaging library.
 * This file is manually maintained — regenerate if the Rust FFI changes.
 */

#ifndef MYCELIUM_H
#define MYCELIUM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Opaque Types --- */

typedef struct MyceliumNode MyceliumNode;

/* --- Data Structures --- */

typedef struct {
    uint8_t  message_id[16];
    uint8_t  source[32];
    uint8_t  destination[32];
    uint8_t  content_type;
    uint64_t timestamp;
    uint8_t  status;
    bool     is_incoming;
    const uint8_t *plaintext;
    uint32_t plaintext_len;
} MessageInfo;

typedef struct {
    uint8_t  peer_id[32];
    uint64_t last_message_time;
    uint32_t unread_count;
} ConversationInfo;

typedef struct {
    uint8_t  peer_id[32];
    uint64_t last_message_time;
    uint32_t message_count;
    bool     has_unread;
} ConversationSummary;

typedef struct {
    uint32_t neighbor_count;
    bool     is_connected;
    uint8_t  battery_level;
    uint32_t dtn_queue_size;
} NetworkStatus;

typedef struct {
    uint8_t  node_id[32];
    uint32_t display_name_len;
    float    trust_score;
    bool     is_verified;
    uint64_t last_seen;
} ContactInfo;

/* --- Callback Types --- */

/** Incoming message notification callback. */
typedef void (*MessageCallback)(
    const uint8_t source[32],
    const uint8_t message_id[16],
    uint8_t content_type,
    uint64_t timestamp
);

/** BLE/WiFi send callback. Returns 0 on success. */
typedef int32_t (*TransportSendCallback)(
    const uint8_t peer_id[32],
    const uint8_t *data,
    uint32_t data_len
);

/* --- Error Retrieval --- */

/** Get the last error message. Returns length written (0 if none). */
int32_t mycelium_last_error(uint8_t *out_buf, uint32_t buf_len);

/** Clear the last error. */
void mycelium_clear_error(void);

/* --- Node Lifecycle --- */

/** Create a new Mycelium node. Returns NULL on failure. */
MyceliumNode *mycelium_node_new(const char *data_dir, const char *display_name);

/** Start the node event loop. Returns true on success. */
bool mycelium_node_start(MyceliumNode *handle);

/** Stop the node. */
void mycelium_node_stop(MyceliumNode *handle);

/** Get the 32-byte node ID. */
void mycelium_node_id(const MyceliumNode *handle, uint8_t out[32]);

/** Free the node handle. Call exactly once. */
void mycelium_node_free(MyceliumNode *handle);

/* --- Messaging --- */

/** Send a message. Returns 0 on success, fills out_message_id. */
int32_t mycelium_send_message(
    MyceliumNode *handle,
    const uint8_t destination[32],
    const uint8_t *data, uint32_t data_len,
    uint8_t content_type,
    uint8_t out_message_id[16]
);

/** Get conversation messages. Returns count written, or negative on error. */
int32_t mycelium_get_messages(
    const MyceliumNode *handle,
    const uint8_t peer_id[32],
    uint32_t limit, uint32_t offset,
    MessageInfo *out_messages, uint32_t out_capacity
);

/** Set callback for incoming message notifications. Pass NULL to unregister. */
int32_t mycelium_set_message_callback(MyceliumNode *handle, MessageCallback callback);

/* --- Conversations --- */

/** List conversations. Returns count written. */
int32_t mycelium_get_conversations(
    const MyceliumNode *handle,
    ConversationSummary *out_conversations,
    uint32_t out_capacity
);

/** Delete all messages in a conversation. Returns 0 on success. */
int32_t mycelium_delete_conversation(MyceliumNode *handle, const uint8_t peer_id[32]);

/** Mark all incoming messages from a peer as read. Returns count marked. */
int32_t mycelium_mark_read(MyceliumNode *handle, const uint8_t peer_id[32]);

/** Get unread count for a specific peer. */
int32_t mycelium_unread_count(const MyceliumNode *handle, const uint8_t peer_id[32]);

/** Get total unread count across all conversations. */
int32_t mycelium_total_unread_count(const MyceliumNode *handle);

/* --- Contacts --- */

/** Get number of contacts. */
int32_t mycelium_contact_count(const MyceliumNode *handle);

/** Get contacts list. Returns count written. */
int32_t mycelium_get_contacts(
    const MyceliumNode *handle,
    ContactInfo *out_contacts, uint32_t out_capacity,
    uint8_t *out_names, uint32_t names_capacity
);

/** Set display name for a contact. */
int32_t mycelium_set_display_name(
    MyceliumNode *handle,
    const uint8_t peer_id[32],
    const char *name
);

/** Get display name for a contact. Returns length written. */
int32_t mycelium_get_display_name(
    const MyceliumNode *handle,
    const uint8_t peer_id[32],
    uint8_t *out_buf, uint32_t buf_len
);

/* --- Groups --- */

/** Create a new group. Returns 0 on success, fills out_group_id. */
int32_t mycelium_create_group(MyceliumNode *handle, uint8_t out_group_id[32]);

/** Add a member to a group. */
int32_t mycelium_add_group_member(
    MyceliumNode *handle,
    const uint8_t group_id[32],
    const uint8_t member_id[32]
);

/** Remove a member from a group. */
int32_t mycelium_remove_group_member(
    MyceliumNode *handle,
    const uint8_t group_id[32],
    const uint8_t member_id[32]
);

/** Get member count for a group. */
int32_t mycelium_group_member_count(const MyceliumNode *handle, const uint8_t group_id[32]);

/** Get group member IDs. Returns count written. */
int32_t mycelium_get_group_members(
    const MyceliumNode *handle,
    const uint8_t group_id[32],
    uint8_t (*out_members)[32], uint32_t out_capacity
);

/** Send a group message. Returns 0 on success. */
int32_t mycelium_send_group_message(
    MyceliumNode *handle,
    const uint8_t group_id[32],
    const uint8_t *data, uint32_t data_len,
    uint8_t content_type,
    uint8_t out_message_id[16]
);

/* --- Trust / Verification --- */

/** Add a trust vouch for a peer. */
int32_t mycelium_add_vouch(MyceliumNode *handle, const uint8_t vouchee_id[32]);

/** Get trust score for a peer (0.0 - 1.0). Returns -1.0 on error. */
float mycelium_trust_score(const MyceliumNode *handle, const uint8_t peer_id[32]);

/** Verify a session (after safety number comparison). Returns 0 on success. */
int32_t mycelium_verify_session(MyceliumNode *handle, const uint8_t peer_id[32]);

/** Get safety number string. Returns length written, or -1 if no session. */
int32_t mycelium_safety_number(
    const MyceliumNode *handle,
    const uint8_t peer_id[32],
    uint8_t *out_buf, uint32_t buf_len
);

/* --- Network Status --- */

/** Get current network status. Returns 0 on success. */
int32_t mycelium_network_status(const MyceliumNode *handle, NetworkStatus *out_status);

/** Update battery state from platform. */
int32_t mycelium_update_battery(MyceliumNode *handle, int16_t battery_level, bool is_charging);

/* --- Transport Registration --- */

/** Register BLE transport. Returns 0 on success. */
int32_t mycelium_register_ble_transport(MyceliumNode *handle);

/** Register Wi-Fi Direct transport. Returns 0 on success. */
int32_t mycelium_register_wifi_direct_transport(MyceliumNode *handle);

/* --- Transport Event Injection (Platform → Rust) --- */

int32_t mycelium_ble_on_peer_discovered(MyceliumNode *handle, const uint8_t peer_id[32]);
int32_t mycelium_ble_on_peer_lost(MyceliumNode *handle, const uint8_t peer_id[32]);
int32_t mycelium_ble_on_data_received(
    MyceliumNode *handle,
    const uint8_t peer_id[32],
    const uint8_t *data, uint32_t data_len
);

int32_t mycelium_wifi_on_peer_connected(MyceliumNode *handle, const uint8_t peer_id[32]);
int32_t mycelium_wifi_on_peer_disconnected(MyceliumNode *handle, const uint8_t peer_id[32]);
int32_t mycelium_wifi_on_data_received(
    MyceliumNode *handle,
    const uint8_t peer_id[32],
    const uint8_t *data, uint32_t data_len
);

/* --- BLE Outbox (Rust → Platform polling) --- */

/** Dequeue one pending BLE send. Returns 1 if dequeued, 0 if empty, -1 on error. */
int32_t mycelium_ble_dequeue_send(
    MyceliumNode *handle,
    uint8_t out_peer_id[32],
    uint8_t *out_data, uint32_t data_capacity,
    uint32_t *out_data_len
);

/* --- Transport Send Callbacks (Rust → Platform) --- */

int32_t mycelium_ble_set_send_callback(MyceliumNode *handle, TransportSendCallback callback);
int32_t mycelium_wifi_set_send_callback(MyceliumNode *handle, TransportSendCallback callback);

#ifdef __cplusplus
}
#endif

#endif /* MYCELIUM_H */
