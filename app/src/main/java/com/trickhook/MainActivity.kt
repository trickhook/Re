package com.trickhook

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.viewmodel.compose.viewModel
import com.trickhook.ui.NocturneTheme
import com.trickhook.ui.StudioApp
import com.trickhook.vm.StudioViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        // Android 15 forces edge-to-edge at targetSdk 35 whether we ask for it
        // or not, so ask for it everywhere: the inset padding in the tree then
        // runs on every supported release instead of only the newest one, and
        // the bars stop being a surprise that only shows up on a Pixel.
        // Called before super.onCreate, which is what the API expects.
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            val vm: StudioViewModel = viewModel()
            NocturneTheme(dark = vm.darkTheme) {
                StudioApp(vm)
            }
        }
    }
}
