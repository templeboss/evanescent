package net.evanescent.model

enum class MessageStatus {
    SENDING,
    SENT,
    DELIVERED,
    FAILED
}

enum class MessageDirection {
    OUTBOUND,
    INBOUND
}
