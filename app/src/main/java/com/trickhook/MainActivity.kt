package com.trickhook

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.lifecycle.viewmodel.compose.viewModel
import com.trickhook.ui.NocturneTheme
import com.trickhook.ui.StudioApp
import com.trickhook.vm.StudioViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val vm: StudioViewModel = viewModel()
            NocturneTheme(dark = vm.darkTheme) {
                StudioApp(vm)
            }
        }
    }
}
