// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

/**
 * The conversation-label rule as the dialog applies it before any FFI call
 * (1.1, L-D5), mirroring core's `normalize_label` (L-D3): trim; empty after
 * trimming clears; at most [MAX_SCALARS] Unicode scalar values (code points,
 * not UTF-16 units and not bytes); no control characters. Pure functions —
 * no Android types — so the plain-JVM suite pins them. Core re-checks on
 * write, so a disagreement here can only make the dialog stricter, never let
 * a bad label through.
 */
object LabelRules {
    /** Core's `MAX_LABEL_SCALARS`. */
    const val MAX_SCALARS: Int = 64

    /** Unicode scalar values in [text] (what the live counter and the cap count). */
    fun scalarCount(text: String): Int = text.codePointCount(0, text.length)

    /**
     * Classifies a dialog draft: [LabelCheck.Clear] for a blank draft (the
     * dialog's Save then clears, like Clear), [LabelCheck.Ok] with the trimmed
     * label, [LabelCheck.TooLong] over the cap, [LabelCheck.Invalid] when a
     * control character is present.
     */
    fun check(draft: String): LabelCheck {
        val trimmed = draft.trim()
        if (trimmed.isEmpty()) return LabelCheck.Clear
        val scalars = scalarCount(trimmed)
        if (scalars > MAX_SCALARS) return LabelCheck.TooLong(scalars)
        if (trimmed.any { Character.isISOControl(it) }) return LabelCheck.Invalid
        return LabelCheck.Ok(trimmed)
    }
}

/** Result of [LabelRules.check]. */
sealed interface LabelCheck {
    /** Blank after trimming: saving clears the label. */
    data object Clear : LabelCheck

    /** Trimmed text within the rule. */
    data class Ok(val label: String) : LabelCheck

    /** More than [LabelRules.MAX_SCALARS] scalar values. */
    data class TooLong(val scalars: Int) : LabelCheck

    /** A control character (tab, line break, NUL, …) is present. */
    data object Invalid : LabelCheck
}
