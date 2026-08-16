@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.securegsi

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            SecureGSITheme {
                SecureGSIApp()
            }
        }
    }
}

@Composable
fun SecureGSITheme(
    content: @Composable () -> Unit
) {
    MaterialTheme {
        content()
    }
}

@Composable
fun SecureGSIApp() {

    var selectedTab by remember {
        mutableIntStateOf(0)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "SecureGSI",
                        fontWeight = FontWeight.Bold
                    )
                },
                actions = {
                    IconButton(
                        onClick = {
                            // Настройки добавим позже
                        }
                    ) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = "Settings"
                        )
                    }
                }
            )
        },

        bottomBar = {
            NavigationBar {

                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = {
                        Icon(
                            Icons.Default.Memory,
                            contentDescription = "Virtual machines"
                        )
                    },
                    label = {
                        Text("VMs")
                    }
                )

                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = {
                        Icon(
                            Icons.Default.Storage,
                            contentDescription = "Images"
                        )
                    },
                    label = {
                        Text("Images")
                    }
                )

                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = {
                        Icon(
                            Icons.Default.Security,
                            contentDescription = "Security"
                        )
                    },
                    label = {
                        Text("Security")
                    }
                )
            }
        }
    ) { paddingValues ->

        when (selectedTab) {

            0 -> DashboardScreen(
                modifier = Modifier.padding(paddingValues)
            )

            1 -> ImagesScreen(
                modifier = Modifier.padding(paddingValues)
            )

            2 -> SecurityScreen(
                modifier = Modifier.padding(paddingValues)
            )
        }
    }
}

@Composable
fun DashboardScreen(
    modifier: Modifier = Modifier
) {

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),

        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {

        item {

            Text(
                text = "Virtual Machines",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )

            Spacer(
                modifier = Modifier.height(4.dp)
            )

            Text(
                text = "Isolated guest operating systems",
                style = MaterialTheme.typography.bodyMedium
            )
        }

        item {
            EmptyVMCard()
        }

        item {

            Text(
                text = "System",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
        }

        item {
            SystemStatusCard()
        }

        item {

            Text(
                text = "Security",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
        }

        item {
            SecuritySummaryCard()
        }
    }
}

@Composable
fun EmptyVMCard() {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = CardDefaults.shape
    ) {

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),

            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Icon(
                imageVector = Icons.Default.Memory,
                contentDescription = null,
                modifier = Modifier.size(48.dp)
            )

            Spacer(
                modifier = Modifier.height(12.dp)
            )

            Text(
                text = "No virtual machines",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )

            Spacer(
                modifier = Modifier.height(6.dp)
            )

            Text(
                text = "Create your first isolated VM.",
                style = MaterialTheme.typography.bodyMedium
            )

            Spacer(
                modifier = Modifier.height(16.dp)
            )

            Button(
                onClick = {
                    // VM creation добавим позже
                }
            ) {

                Icon(
                    imageVector = Icons.Default.Add,
                    contentDescription = null
                )

                Spacer(
                    modifier = Modifier.size(8.dp)
                )

                Text("Create VM")
            }
        }
    }
}

@Composable
fun SystemStatusCard() {

    val context = LocalContext.current

    val status = remember {
        SystemStatusReader.read(context)
    }

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {

        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {

            StatusRow(
                name = "Device",
                value = "${status.manufacturer} ${status.device}"
            )

            HorizontalDivider()

            StatusRow(
                name = "Android",
                value = "${status.androidVersion} (API ${status.sdkVersion})"
            )

            HorizontalDivider()

            StatusRow(
                name = "Architecture",
                value = status.architecture
            )

            HorizontalDivider()

            StatusRow(
                name = "AVF",
                value = if (status.avfAvailable) {
                    "Available"
                } else {
                    "Not available"
                }
            )

            HorizontalDivider()

            StatusRow(
                name = "Protected KVM",
                value = if (status.protectedKvmAvailable) {
                    "Potentially available"
                } else {
                    "Not detected"
                }
            )
        }
    }
}

@Composable
fun SecuritySummaryCard() {

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {

        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {

            StatusRow(
                name = "VM isolation",
                value = "Not configured"
            )

            HorizontalDivider()

            StatusRow(
                name = "Storage encryption",
                value = "Not configured"
            )

            HorizontalDivider()

            StatusRow(
                name = "Network isolation",
                value = "Not configured"
            )
        }
    }
}

@Composable
fun StatusRow(
    name: String,
    value: String
) {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {

        Text(
            text = name,
            style = MaterialTheme.typography.bodyLarge
        )

        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
fun ImagesScreen(
    modifier: Modifier = Modifier
) {

    val context = LocalContext.current

    var selectedImage by remember {
        mutableStateOf<ImageInfo?>(null)
    }

    val launcher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->

        if (uri != null) {

            try {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } catch (_: SecurityException) {
                // Некоторые файловые провайдеры не поддерживают
                // постоянное разрешение.
            }

            selectedImage = ImageManager.getImageInfo(
                context,
                uri
            )
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(20.dp)
    ) {

        Text(
            text = "Images",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )

        Spacer(
            modifier = Modifier.height(8.dp)
        )

        Text(
            text = "GSI and VM images",
            style = MaterialTheme.typography.bodyMedium
        )

        Spacer(
            modifier = Modifier.height(24.dp)
        )

        Button(
            onClick = {

                launcher.launch(
                    arrayOf(
                        "application/octet-stream",
                        "application/zip",
                        "application/x-raw-disk-image",
                        "*/*"
                    )
                )
            }
        ) {

            Icon(
                imageVector = Icons.Default.Storage,
                contentDescription = null
            )

            Spacer(
                modifier = Modifier.size(8.dp)
            )

            Text("Import image")
        }

        Spacer(
            modifier = Modifier.height(24.dp)
        )

        selectedImage?.let { image ->

            Card(
                modifier = Modifier.fillMaxWidth()
            ) {

                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {

                    Text(
                        text = image.name,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )

                    HorizontalDivider()

                    StatusRow(
                        name = "Size",
                        value = formatFileSize(image.size)
                    )

                    StatusRow(
                        name = "Status",
                        value = "Imported"
                    )
                }
            }
        }
    }
}

fun formatFileSize(size: Long): String {

    if (size <= 0) {
        return "Unknown"
    }

    val units = arrayOf(
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    )

    var value = size.toDouble()
    var index = 0

    while (
        value >= 1024 &&
        index < units.lastIndex
    ) {
        value /= 1024
        index++
    }

    return String.format(
        "%.2f %s",
        value,
        units[index]
    )
}

@Composable
fun SecurityScreen(
    modifier: Modifier = Modifier
) {

    val securityOptions = listOf(
        "Storage encryption" to "Encrypt VM storage",
        "Network isolation" to "Restrict guest network access",
        "Integrity verification" to "Verify VM images before startup"
    )

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(20.dp),

        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {

        item {

            Text(
                text = "Security",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )

            Spacer(
                modifier = Modifier.height(8.dp)
            )

            Text(
                text = "Security policies for virtual machines.",
                style = MaterialTheme.typography.bodyMedium
            )
        }

        items(securityOptions) { option ->

            SecurityOption(
                title = option.first,
                description = option.second
            )
        }
    }
}

@Composable
fun SecurityOption(
    title: String,
    description: String
) {

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),

            verticalAlignment = Alignment.CenterVertically
        ) {

            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = null
            )

            Spacer(
                modifier = Modifier.size(12.dp)
            )

            Column {

                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )

                Text(
                    text = description,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
    }
}