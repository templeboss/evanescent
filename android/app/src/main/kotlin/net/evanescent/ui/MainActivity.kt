package net.evanescent.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import net.evanescent.ui.contact.AddContactScreen
import net.evanescent.ui.contact.SafetyNumberScreen
import net.evanescent.ui.conversation.ConversationListScreen
import net.evanescent.ui.conversation.ConversationScreen
import net.evanescent.ui.settings.SettingsScreen

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val navController = rememberNavController()
                    NavHost(navController = navController, startDestination = "conversations") {
                        composable("conversations") {
                            ConversationListScreen(
                                onConversationClick = { contactIdHex ->
                                    navController.navigate("conversation/$contactIdHex")
                                },
                                onAddContact = { navController.navigate("add_contact") },
                                onSettings = { navController.navigate("settings") }
                            )
                        }
                        composable("conversation/{contactIdHex}") { backStack ->
                            val contactIdHex = backStack.arguments?.getString("contactIdHex") ?: return@composable
                            ConversationScreen(
                                contactIdHex = contactIdHex,
                                onBack = { navController.popBackStack() },
                                onSafetyNumber = { navController.navigate("safety_number/$contactIdHex") }
                            )
                        }
                        composable("add_contact") {
                            AddContactScreen(onDone = { navController.popBackStack() })
                        }
                        composable("safety_number/{contactIdHex}") { backStack ->
                            val contactIdHex = backStack.arguments?.getString("contactIdHex") ?: return@composable
                            SafetyNumberScreen(
                                contactIdHex = contactIdHex,
                                onBack = { navController.popBackStack() }
                            )
                        }
                        composable("settings") {
                            SettingsScreen(onBack = { navController.popBackStack() })
                        }
                    }
                }
            }
        }
    }
}
