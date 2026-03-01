package net.evanescent.ui.settings

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
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
import androidx.lifecycle.viewmodel.compose.viewModel
import net.evanescent.App
import net.evanescent.provider.OrbotHelper
import net.evanescent.provider.ProviderService
import net.evanescent.util.toHex

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    viewModel: SettingsViewModel = viewModel()
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    var onionAddress by remember { mutableStateOf(viewModel.getSavedOnionAddress() ?: "") }
    var bundleCopied by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
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
                .fillMaxSize()
        ) {
            Text("Identity", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                text = "Key: ${app.identityPub.toHex().take(16)}…",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
            )

            Spacer(Modifier.height(24.dp))
            Text("Provider", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

            OutlinedTextField(
                value = onionAddress,
                onValueChange = { onionAddress = it },
                label = { Text("Provider .onion address") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                isError = onionAddress.isNotEmpty() && !OrbotHelper.isValidOnionAddress(onionAddress)
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    viewModel.saveOnionAddress(onionAddress)
                    ProviderService.start(app, onionAddress)
                },
                enabled = OrbotHelper.isValidOnionAddress(onionAddress)
            ) {
                Text("Connect to Provider")
            }

            // Show Contact Bundle section once provider Nym address is known.
            val nymAddr = app.providerNymAddr
            if (nymAddr.isNotEmpty() && OrbotHelper.isValidOnionAddress(onionAddress)) {
                Spacer(Modifier.height(24.dp))
                Text("Contact Bundle", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Text(
                    "Share this with contacts so they can add you.",
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = {
                        val bundle = viewModel.buildContactBundle(app.identityPub, nymAddr, onionAddress)
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("Contact Bundle", bundle))
                        bundleCopied = true
                    }
                ) {
                    Text("Copy Contact Bundle")
                }
                if (bundleCopied) {
                    Spacer(Modifier.height(4.dp))
                    Text("Copied to clipboard.", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary)
                }
            }
        }
    }
}

class SettingsViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("settings", Context.MODE_PRIVATE)

    fun getSavedOnionAddress(): String? = prefs.getString("onion_address", null)

    fun saveOnionAddress(address: String) {
        prefs.edit().putString("onion_address", address).apply()
    }

    /**
     * Encode a ContactBundle proto (minimal hand-rolled encoding):
     *   field 1 (bytes): identity_key
     *   field 2 (string): nym_address
     *   field 3 (string): provider_onion
     *   field 4 (varint): version = 1
     */
    fun buildContactBundle(identityKey: ByteArray, nymAddress: String, onionAddress: String): String {
        val nymBytes = nymAddress.toByteArray(Charsets.UTF_8)
        val onionBytes = onionAddress.toByteArray(Charsets.UTF_8)
        val payload = encodeBytes(1, identityKey) +
            encodeBytes(2, nymBytes) +
            encodeBytes(3, onionBytes) +
            encodeTag(4, 0) + encodeVarint(1L)  // version = 1
        return Base64.encodeToString(payload, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    private fun encodeBytes(fieldNum: Int, data: ByteArray): ByteArray =
        encodeTag(fieldNum, 2) + encodeVarint(data.size.toLong()) + data

    private fun encodeTag(fieldNum: Int, wireType: Int): ByteArray =
        encodeVarint(((fieldNum.toLong() shl 3) or wireType.toLong()))

    private fun encodeVarint(v: Long): ByteArray {
        val buf = mutableListOf<Byte>()
        var rem = v
        do {
            var b = (rem and 0x7F).toByte()
            rem = rem ushr 7
            if (rem != 0L) b = (b.toInt() or 0x80).toByte()
            buf.add(b)
        } while (rem != 0L)
        return buf.toByteArray()
    }
}

private operator fun ByteArray.plus(other: ByteArray): ByteArray {
    val result = ByteArray(size + other.size)
    System.arraycopy(this, 0, result, 0, size)
    System.arraycopy(other, 0, result, size, other.size)
    return result
}
