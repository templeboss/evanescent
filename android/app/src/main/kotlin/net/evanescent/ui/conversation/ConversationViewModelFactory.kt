package net.evanescent.ui.conversation

import android.app.Application
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider

class ConversationViewModelFactory(
    private val app: Application,
    private val contactIdHex: String
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        @Suppress("UNCHECKED_CAST")
        return ConversationViewModel(app, contactIdHex) as T
    }
}
