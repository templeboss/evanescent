package net.evanescent.ui.conversation

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import net.evanescent.util.toHex
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationListScreen(
    onConversationClick: (String) -> Unit,
    onAddContact: () -> Unit,
    onSettings: () -> Unit,
    viewModel: ConversationListViewModel = viewModel()
) {
    val conversations by viewModel.conversations.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Evanescent") },
                actions = {
                    IconButton(onClick = onSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAddContact) {
                Icon(Icons.Default.Add, contentDescription = "Add contact")
            }
        }
    ) { padding ->
        LazyColumn(contentPadding = padding) {
            items(conversations) { item ->
                ListItem(
                    headlineContent = { Text(item.contact.alias.ifBlank { "Unknown" }) },
                    supportingContent = {
                        item.lastMessage?.let { msg ->
                            Text(
                                text = msg.plaintext.take(50),
                                maxLines = 1
                            )
                        }
                    },
                    trailingContent = {
                        item.lastMessage?.let { msg ->
                            Text(
                                text = formatTime(msg.timestamp),
                                style = MaterialTheme.typography.labelSmall
                            )
                        }
                    },
                    modifier = Modifier.clickable {
                        onConversationClick(item.contact.identityKey.toHex())
                    }
                )
                Divider()
            }
        }
    }
}

private val timeFormat = SimpleDateFormat("HH:mm", Locale.getDefault())
private val dateFormat = SimpleDateFormat("MMM d", Locale.getDefault())

private fun formatTime(timestamp: Long): String {
    val now = System.currentTimeMillis()
    return if (now - timestamp < 24 * 3600 * 1000) {
        timeFormat.format(Date(timestamp))
    } else {
        dateFormat.format(Date(timestamp))
    }
}
