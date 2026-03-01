package net.evanescent.ui.contact

import android.app.Application
import android.util.Base64
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch
import net.evanescent.App
import net.evanescent.db.ContactEntity

/**
 * Screen for adding a contact by scanning or pasting a ContactBundle.
 * ContactBundle is base64url-encoded proto bytes.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddContactScreen(
    onDone: () -> Unit,
    viewModel: AddContactViewModel = viewModel()
) {
    var bundleText by remember { mutableStateOf("") }
    var alias by remember { mutableStateOf("") }
    val status by viewModel.status.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Add Contact") },
                navigationIcon = {
                    IconButton(onClick = onDone) {
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
                .fillMaxSize()
        ) {
            Text("Paste a Contact Bundle (base64url)", style = MaterialTheme.typography.labelMedium)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = bundleText,
                onValueChange = { bundleText = it },
                label = { Text("Contact Bundle") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = false,
                minLines = 3
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = alias,
                onValueChange = { alias = it },
                label = { Text("Alias (optional)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = {
                    viewModel.addContact(bundleText.trim(), alias.trim())
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = bundleText.isNotBlank()
            ) {
                Text("Add Contact")
            }

            status?.let { msg ->
                Spacer(Modifier.height(8.dp))
                Text(msg, color = if (msg.startsWith("Error")) MaterialTheme.colorScheme.error
                              else MaterialTheme.colorScheme.primary)
                if (msg == "Contact added.") {
                    LaunchedEffect(Unit) { onDone() }
                }
            }
        }
    }
}

class AddContactViewModel(app: Application) : AndroidViewModel(app) {
    private val db = (app as App).database
    private val _status = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)
    val status = _status

    fun addContact(bundleBase64: String, alias: String) {
        viewModelScope.launch {
            try {
                val bytes = Base64.decode(
                    bundleBase64.replace('-', '+').replace('_', '/'),
                    Base64.NO_WRAP or Base64.NO_PADDING
                )
                val bundle = parseContactBundle(bytes)
                db.contactDao().upsert(ContactEntity(
                    identityKey = bundle.identityKey,
                    nymAddress = bundle.nymAddress,
                    providerOnion = bundle.providerOnion,
                    alias = alias.ifBlank { bundle.nymAddress.take(16) }
                ))
                _status.value = "Contact added."
            } catch (e: Exception) {
                _status.value = "Error: ${e.message}"
            }
        }
    }

    private data class ContactBundle(
        val identityKey: ByteArray,
        val nymAddress: String,
        val providerOnion: String,
        val version: Int
    )

    private fun parseContactBundle(bytes: ByteArray): ContactBundle {
        var pos = 0
        var identityKey = byteArrayOf()
        var nymAddress = ""
        var providerOnion = ""
        var version = 0

        while (pos < bytes.size) {
            val (tag, n) = readVarint(bytes, pos); pos += n
            val fieldNum = (tag shr 3).toInt()
            val wireType = (tag and 0x7).toInt()
            if (wireType == 2) {
                val (len, n2) = readVarint(bytes, pos); pos += n2
                val v = bytes.copyOfRange(pos, pos + len.toInt()); pos += len.toInt()
                when (fieldNum) {
                    1 -> identityKey = v
                    2 -> nymAddress = String(v, Charsets.UTF_8)
                    3 -> providerOnion = String(v, Charsets.UTF_8)
                }
            } else if (wireType == 0) {
                val (v, n2) = readVarint(bytes, pos); pos += n2
                if (fieldNum == 4) version = v.toInt()
            } else {
                pos += skipField(bytes, pos, wireType)
            }
        }
        require(identityKey.size == 32) { "Invalid identity key" }
        return ContactBundle(identityKey, nymAddress, providerOnion, version)
    }

    private fun readVarint(data: ByteArray, start: Int): Pair<Long, Int> {
        var result = 0L; var shift = 0; var pos = start
        while (pos < data.size) {
            val b = data[pos++].toInt() and 0xFF
            result = result or ((b and 0x7F).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) break
        }
        return Pair(result, pos - start)
    }

    private fun skipField(data: ByteArray, pos: Int, wireType: Int): Int {
        return when (wireType) {
            0 -> { var p = pos; while (p < data.size && data[p].toInt() and 0x80 != 0) p++; p + 1 - pos }
            2 -> { val (len, n) = readVarint(data, pos); n + len.toInt() }
            5 -> 4
            1 -> 8
            else -> 0
        }
    }
}
