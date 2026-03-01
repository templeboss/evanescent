package net.evanescent.ui.conversation

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.*
import net.evanescent.App
import net.evanescent.db.ContactEntity
import net.evanescent.db.MessageEntity

class ConversationListViewModel(app: Application) : AndroidViewModel(app) {

    private val db = (app as App).database

    data class ConversationItem(
        val contact: ContactEntity,
        val lastMessage: MessageEntity?
    )

    val conversations: StateFlow<List<ConversationItem>> = db.contactDao()
        .getAllFlow()
        .flatMapLatest { contacts ->
            if (contacts.isEmpty()) {
                flowOf(emptyList())
            } else {
                combine(contacts.map { contact ->
                    db.messageDao().getForContactFlow(contact.identityKey)
                        .map { msgs ->
                            ConversationItem(contact, msgs.lastOrNull())
                        }
                }) { it.toList() }
            }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
}
