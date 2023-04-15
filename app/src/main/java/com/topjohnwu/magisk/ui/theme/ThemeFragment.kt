package com.topjohnwu.magisk.ui.theme

import android.os.Build
import android.os.Bundle
import android.view.*
import android.widget.LinearLayout
import com.topjohnwu.magisk.BR
import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.arch.BaseFragment
import com.topjohnwu.magisk.arch.viewModel
import com.topjohnwu.magisk.databinding.FragmentThemeBinding
import com.topjohnwu.magisk.databinding.ItemThemeBindingImpl

class ThemeFragment : BaseFragment<FragmentThemeBinding>() {

    override val layoutRes = R.layout.fragment_theme
    override val viewModel by viewModel<ThemeViewModel>()

    override fun onStart() {
        super.onStart()
        setHasOptionsMenu(true)
        activity?.title = getString(R.string.settings_theme_color)
    }
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        super.onCreateView(inflater, container, savedInstanceState)

        val view = binding.root.findViewById<LinearLayout>(R.id.theme_container)

        for(a in Theme.values()){
            if(Build.VERSION.SDK_INT < Build.VERSION_CODES.S && ((a == Theme.Dynamic) || (a == Theme.DynamicBlack)))
                continue
            val themed = ContextThemeWrapper(activity, a.themeRes)
            ItemThemeBindingImpl.inflate(LayoutInflater.from(themed), view, true).also {
                it.setVariable(BR.viewModel, viewModel)
                it.setVariable(BR.theme, a)
                it.lifecycleOwner = viewLifecycleOwner
            }

        }

        return binding.root
    }
}