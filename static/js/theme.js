(function () {
    const THEME_KEY = "logsec-theme";
    const DEFAULT_THEME = "dark";

    /**
     * Read the saved theme.
     * Invalid or missing values use dark mode.
     */
    function getSavedTheme() {
        try {
            const savedTheme = localStorage.getItem(THEME_KEY);

            if (savedTheme === "light" || savedTheme === "dark") {
                return savedTheme;
            }
        } catch (error) {
            console.warn("LogSec could not read the saved theme.");
        }

        return DEFAULT_THEME;
    }

    /**
     * Apply a theme to the HTML document.
     */
    function applyTheme(theme) {
        const validTheme =
            theme === "light" ? "light" : "dark";

        document.documentElement.setAttribute(
            "data-theme",
            validTheme
        );

        document.documentElement.style.colorScheme = validTheme;

        updateThemeButtons(validTheme);

        return validTheme;
    }

    /**
     * Save the selected theme.
     */
    function saveTheme(theme) {
        try {
            localStorage.setItem(THEME_KEY, theme);
        } catch (error) {
            console.warn("LogSec could not save the theme.");
        }
    }

    /**
     * Update all theme buttons on the current page.
     */
    function updateThemeButtons(theme) {
        const buttons = document.querySelectorAll(
            "[data-theme-toggle]"
        );

        buttons.forEach(function (button) {
            const isLight = theme === "light";

            button.setAttribute(
                "aria-label",
                isLight ? "Switch to dark mode" : "Switch to light mode"
            );

            button.setAttribute(
                "aria-pressed",
                String(isLight)
            );

            const label = button.querySelector(
                "[data-theme-label]"
            );

            if (label) {
                label.textContent = isLight
                    ? "Dark mode"
                    : "Light mode";
            } else {
                button.textContent = isLight
                    ? "🌙 Dark mode"
                    : "☀️ Light mode";
            }

            const icon = button.querySelector(
                "[data-theme-icon]"
            );

            if (icon) {
                icon.textContent = isLight ? "🌙" : "☀️";
            }
        });
    }

    /**
     * Switch between dark and light themes.
     */
    function toggleTheme() {
        const currentTheme =
            document.documentElement.getAttribute("data-theme") ||
            DEFAULT_THEME;

        const nextTheme =
            currentTheme === "dark" ? "light" : "dark";

        const appliedTheme = applyTheme(nextTheme);

        saveTheme(appliedTheme);

        /*
         * Notify components such as charts that
         * the theme has changed.
         */
        document.dispatchEvent(
            new CustomEvent("logsec:themechange", {
                detail: {
                    theme: appliedTheme
                }
            })
        );
    }

    /**
     * Initialize the theme and button events.
     */
    function initializeTheme() {
        const initialTheme = applyTheme(getSavedTheme());

        /*
         * Event delegation allows theme buttons to work
         * even if a page contains multiple buttons.
         */
        document.addEventListener("click", function (event) {
            const button = event.target.closest(
                "[data-theme-toggle]"
            );

            if (!button) {
                return;
            }

            event.preventDefault();
            toggleTheme();
        });

        /*
         * Make theme functions available for optional
         * integration with other LogSec scripts.
         */
        window.LogSecTheme = {
            getTheme: function () {
                return (
                    document.documentElement.getAttribute("data-theme") ||
                    DEFAULT_THEME
                );
            },

            setTheme: function (theme) {
                const appliedTheme = applyTheme(theme);

                saveTheme(appliedTheme);

                document.dispatchEvent(
                    new CustomEvent("logsec:themechange", {
                        detail: {
                            theme: appliedTheme
                        }
                    })
                );
            },

            toggleTheme: toggleTheme
        };

        /*
         * Ensure the selected theme is reflected
         * in the document after initialization.
         */
        document.documentElement.setAttribute(
            "data-theme",
            initialTheme
        );
    }

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            initializeTheme,
            { once: true }
        );
    } else {
        initializeTheme();
    }
})();

