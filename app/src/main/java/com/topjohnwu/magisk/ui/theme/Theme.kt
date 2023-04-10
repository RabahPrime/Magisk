package com.topjohnwu.magisk.ui.theme

import android.content.res.Configuration
import android.content.res.Configuration.UI_MODE_NIGHT_YES
import com.topjohnwu.magisk.R
import com.topjohnwu.magisk.core.Config
import com.topjohnwu.magisk.core.Config.context
import com.topjohnwu.magisk.utils.TextHolder
import com.topjohnwu.magisk.utils.asText

enum class Theme(
    val themeName: TextHolder,
    val themeRes: Int
) {
    Dynamic(
        themeName = R.string.color_dynamic.asText(),
        themeRes = R.style.MaterialTheme_Dynamic
    ),
    DynamicBlack(
        themeName = R.string.color_dynamic_black.asText(),
        themeRes = R.style.MaterialTheme_Dynamic_Black
    ),
    Carmine(
        themeName = R.string.color_carmine.asText(),
        themeRes = R.style.MaterialTheme_Carmine
    ),
    Blush(
        themeName = R.string.color_blush.asText(),
        themeRes = R.style.MaterialTheme_Blush
    ),
    Magenta(
        themeName = R.string.color_magenta.asText(),
        themeRes = R.style.MaterialTheme_Magenta
    ),
    Lavender(
        themeName = R.string.color_lavender.asText(),
        themeRes = R.style.MaterialTheme_Lavender
    ),
    Periwinkle(
        themeName = R.string.color_periwinkle.asText(),
        themeRes = R.style.MaterialTheme_Periwinkle
    ),
    Cerulean(
        themeName = R.string.color_cerulean.asText(),
        themeRes = R.style.MaterialTheme_Cerulean
    ),
    Turquoise(
        themeName = R.string.color_turquoise.asText(),
        themeRes = R.style.MaterialTheme_Turquoise
    ),
    Viridian(
        themeName = R.string.color_viridian.asText(),
        themeRes = R.style.MaterialTheme_Viridian
    ),
    Chartreuse(
        themeName = R.string.color_chartreuse.asText(),
        themeRes = R.style.MaterialTheme_Chartreuse
    ),
    Citrine(
        themeName = R.string.color_citrine.asText(),
        themeRes = R.style.MaterialTheme_Citrine
    );

    val isSelected get() = Config.themeOrdinal == ordinal

    fun select() {
        Config.themeOrdinal = ordinal
    }
    
    companion object {
        val selected get() = values().getOrNull(Config.themeOrdinal) ?: Blush
    }

}
