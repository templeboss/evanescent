package net.evanescent.ui.contact

import android.app.Application
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import net.evanescent.App
import net.evanescent.crypto.SafetyNumber
import net.evanescent.util.fromHex

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SafetyNumberScreen(
    contactIdHex: String,
    onBack: () -> Unit,
    viewModel: SafetyNumberViewModel = viewModel()
) {
    LaunchedEffect(contactIdHex) {
        viewModel.load(contactIdHex)
    }

    val safetyNumber by viewModel.safetyNumber.collectAsState()
    val alias by viewModel.alias.collectAsState()
    val verified by viewModel.verified.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Safety Number") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = alias ?: "Unknown",
                style = MaterialTheme.typography.headlineSmall
            )
            Spacer(Modifier.height(24.dp))
            Text(
                text = "Compare this number with your contact over a secure channel.",
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(24.dp))
            safetyNumber?.let { sn ->
                Text(
                    text = sn,
                    style = MaterialTheme.typography.headlineMedium.copy(fontFamily = FontFamily.Monospace),
                    textAlign = TextAlign.Center,
                    letterSpacing = androidx.compose.ui.unit.TextUnit.Unspecified
                )
            } ?: CircularProgressIndicator()
            Spacer(Modifier.height(32.dp))
            if (verified == true) {
                Text(
                    "Verified",
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.labelLarge
                )
            } else {
                Button(onClick = { viewModel.markVerified(contactIdHex) }) {
                    Text("Mark as Verified")
                }
            }
        }
    }
}

class SafetyNumberViewModel(app: Application) : AndroidViewModel(app) {
    private val appInstance = app as App
    private val db = appInstance.database

    val safetyNumber = MutableStateFlow<String?>(null)
    val alias = MutableStateFlow<String?>(null)
    val verified = MutableStateFlow<Boolean?>(null)

    fun load(contactIdHex: String) {
        viewModelScope.launch {
            val contactId = contactIdHex.fromHex()
            val contact = db.contactDao().getByKey(contactId) ?: return@launch
            alias.value = contact.alias
            verified.value = contact.verified != 0
            val sn = SafetyNumber.compute(appInstance.identityPub, contact.identityKey)
            safetyNumber.value = sn
        }
    }

    fun markVerified(contactIdHex: String) {
        viewModelScope.launch {
            db.contactDao().markVerified(contactIdHex.fromHex())
            verified.value = true
        }
    }
}
