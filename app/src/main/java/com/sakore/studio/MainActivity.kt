package com.sakore.studio

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sakore.studio.ui.SakoTheme
import com.sakore.studio.ui.StudioApp
import com.sakore.studio.vm.StudioViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val vm: StudioViewModel = viewModel()
            SakoTheme(dark = vm.darkTheme) {
                StudioApp(vm)
            }
        }
    }
}
