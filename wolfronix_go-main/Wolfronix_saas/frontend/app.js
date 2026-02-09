// ============================================
// WOLFRONIX - CYBER-INDUSTRIAL 3D THEME
// Main JavaScript File
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    initializeLoader();
    initializeTheme();
    initializeMobileMenu();
    initializeSmoothScroll();
    initializeAnimations();
    initializeFormValidation();
    initializeHeroVideo();
    initializeScrambleText();
    initializeHorizontalScroll();
});

// ============================================
// HORIZONTAL SCROLL SECTION
// ============================================

function initializeHorizontalScroll() {
    const wrapper = document.getElementById('horizontalScrollWrapper');
    const track = document.getElementById('horizontalTrack');
    const items = document.querySelectorAll('.horizontal-item');

    if (!wrapper || !track) return;

    items.forEach((item) => {
        item.style.opacity = '1';
    });

    track.style.transform = 'translateX(0)';

    const path = document.getElementById('processLinePath');
    if (path) {
        // Initialize path if not set
        if (!path.style.strokeDasharray) {
            const length = path.getTotalLength();
            path.style.strokeDasharray = length;
            path.style.strokeDashoffset = length;
        }
    }

    let ticking = false;

    const onScroll = () => {
        if (!ticking) {
            window.requestAnimationFrame(() => {
                handleScroll();
                ticking = false;
            });
            ticking = true;
        }
    };

    const handleScroll = () => {
        if (!wrapper || !track) return; // Safety check

        const rect = wrapper.getBoundingClientRect();
        const windowHeight = window.innerHeight;

        const scrollableDistance = wrapper.offsetHeight - windowHeight;
        const scrolledIntoWrapper = -rect.top;

        if (path) {
            const length = path.getTotalLength();
            // Calculate drawing progress
            // We want the line to be fully drawn when we reach the end
            let drawProgress = scrolledIntoWrapper / scrollableDistance;
            drawProgress = Math.max(0, Math.min(1, drawProgress));

            // Update stroke-dashoffset
            path.style.strokeDashoffset = length - (length * drawProgress);
        }

        if (scrolledIntoWrapper <= 0) {
            track.style.transform = 'translateX(0)';
            return;
        }

        if (scrolledIntoWrapper >= scrollableDistance) {
            const maxScroll = track.scrollWidth - window.innerWidth;
            track.style.transform = `translateX(-${maxScroll}px)`;
            return;
        }

        let progress = scrolledIntoWrapper / scrollableDistance;
        progress = Math.max(0, Math.min(1, progress));

        const maxScroll = track.scrollWidth - window.innerWidth;
        const translateX = progress * maxScroll;

        track.style.transform = `translateX(-${translateX}px)`;
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    // Initial call
    handleScroll();
}

// ============================================
// LOADING SCREEN
// ============================================

function initializeLoader() {
    const loader = document.getElementById('pageLoader');
    const loaderBar = document.getElementById('loaderBar');

    if (!loader || !loaderBar) return;

    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress >= 100) {
            progress = 100;
            clearInterval(interval);
            setTimeout(() => {
                loader.classList.add('hidden');
            }, 500);
        }
        loaderBar.style.width = progress + '%';
    }, 100);
}

// ============================================
// SCRAMBLE TEXT EFFECT
// ============================================

function initializeScrambleText() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';

    document.querySelectorAll('.scramble-text').forEach(element => {
        const originalText = element.textContent;
        let iteration = 0;

        const interval = setInterval(() => {
            element.textContent = originalText
                .split('')
                .map((char, index) => {
                    if (index < iteration) {
                        return originalText[index];
                    }
                    return chars[Math.floor(Math.random() * chars.length)];
                })
                .join('');

            if (iteration >= originalText.length) {
                clearInterval(interval);
            }

            iteration += 1 / 3;
        }, 30);
    });
}

// ============================================
// THEME MANAGEMENT
// ============================================

function initializeTheme() {
    const themeToggle = document.querySelector('.theme-toggle');
    const html = document.documentElement;

    // Force dark theme for cyber aesthetic
    html.classList.remove('light');
    html.classList.add('dark');
    localStorage.setItem('theme', 'dark');

    if (themeToggle) {
        themeToggle.style.display = 'none';
    }
}

// ============================================
// MOBILE MENU
// ============================================

function initializeMobileMenu() {
    const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
    const mobileMenu = document.querySelector('.mobile-menu');
    const mobileNavLinks = document.querySelectorAll('.mobile-nav-link');

    if (mobileMenuToggle && mobileMenu) {
        mobileMenuToggle.addEventListener('click', () => {
            const isOpen = mobileMenu.classList.contains('active');

            mobileMenu.classList.toggle('active');
            mobileMenuToggle.setAttribute('aria-expanded', !isOpen);
            mobileMenu.setAttribute('aria-hidden', isOpen);

            // Toggle body scroll
            document.body.style.overflow = isOpen ? '' : 'hidden';

            // Animate hamburger icon
            const spans = mobileMenuToggle.querySelectorAll('span');
            if (!isOpen) {
                spans[0].style.transform = 'rotate(45deg) translateY(8px)';
                spans[1].style.opacity = '0';
                spans[2].style.transform = 'rotate(-45deg) translateY(-8px)';
            } else {
                spans[0].style.transform = '';
                spans[1].style.opacity = '';
                spans[2].style.transform = '';
            }
        });

        // Close menu when clicking on links
        mobileNavLinks.forEach(link => {
            link.addEventListener('click', () => {
                mobileMenu.classList.remove('active');
                mobileMenuToggle.setAttribute('aria-expanded', 'false');
                mobileMenu.setAttribute('aria-hidden', 'true');
                document.body.style.overflow = '';

                // Reset hamburger icon
                const spans = mobileMenuToggle.querySelectorAll('span');
                spans[0].style.transform = '';
                spans[1].style.opacity = '';
                spans[2].style.transform = '';
            });
        });

        // Close menu on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && mobileMenu.classList.contains('active')) {
                mobileMenu.classList.remove('active');
                mobileMenuToggle.setAttribute('aria-expanded', 'false');
                mobileMenu.setAttribute('aria-hidden', 'true');
                document.body.style.overflow = '';
                mobileMenuToggle.focus();
            }
        });
    }
}

// ============================================
// SMOOTH SCROLL
// ============================================

function initializeSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const href = this.getAttribute('href');

            // Ignore empty anchors and non-section links
            if (href === '#' || href === '#demo') {
                e.preventDefault();
                return;
            }

            const target = document.querySelector(href);
            if (target) {
                e.preventDefault();

                const navbarHeight = document.querySelector('.navbar')?.offsetHeight || 0;
                const targetPosition = target.offsetTop - navbarHeight - 20;

                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });

                // Update focus for accessibility
                target.setAttribute('tabindex', '-1');
                target.focus();
            }
        });
    });
}

// ============================================
// SCROLL ANIMATIONS
// ============================================

function initializeAnimations() {
    // Intersection Observer for scroll animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    // Observe elements for animation
    const animatedElements = document.querySelectorAll(`
        .feature-card,
        .pricing-card,
        .process-step,
        .contact-method
    `);

    animatedElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });

    // Navbar scroll effect
    const navbar = document.querySelector('.navbar');

    window.addEventListener('scroll', () => {
        const currentScroll = window.pageYOffset;

        if (currentScroll > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });
}

// ============================================
// FORM VALIDATION
// ============================================

function initializeFormValidation() {
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        const inputs = form.querySelectorAll('input[required], textarea[required]');

        form.addEventListener('submit', (e) => {
            let isValid = true;

            inputs.forEach(input => {
                if (!validateField(input)) {
                    isValid = false;
                }
            });

            if (!isValid) {
                e.preventDefault();
                const firstInvalid = form.querySelector('.error');
                if (firstInvalid) {
                    firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    firstInvalid.focus();
                }
            }
        });

        // Real-time validation
        inputs.forEach(input => {
            input.addEventListener('blur', () => validateField(input));
            input.addEventListener('input', () => clearError(input));
        });
    });
}

function validateField(field) {
    const value = field.value.trim();
    const fieldType = field.type;
    let isValid = true;
    let errorMessage = '';

    // Required field validation
    if (field.hasAttribute('required') && !value) {
        isValid = false;
        errorMessage = `${getFieldLabel(field)} is required`;
    }
    // Email validation
    else if (fieldType === 'email' && value) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
            isValid = false;
            errorMessage = 'Please enter a valid email address';
        }
    }
    // Password validation
    else if (fieldType === 'password' && value && field.hasAttribute('minlength')) {
        const minLength = parseInt(field.getAttribute('minlength'));
        if (value.length < minLength) {
            isValid = false;
            errorMessage = `Password must be at least ${minLength} characters`;
        }
    }

    if (isValid) {
        clearError(field);
    } else {
        showError(field, errorMessage);
    }

    return isValid;
}

function showError(field, message) {
    clearError(field);

    field.classList.add('error');
    field.setAttribute('aria-invalid', 'true');
    field.style.borderColor = '#EF4444';

    const errorElement = document.createElement('div');
    errorElement.className = 'error-message';
    errorElement.textContent = message;
    errorElement.style.color = '#EF4444';
    errorElement.style.fontSize = '0.875rem';
    errorElement.style.marginTop = '0.25rem';

    field.parentNode.appendChild(errorElement);
}

function clearError(field) {
    field.classList.remove('error');
    field.setAttribute('aria-invalid', 'false');
    field.style.borderColor = '';

    const errorElement = field.parentNode.querySelector('.error-message');
    if (errorElement) {
        errorElement.remove();
    }
}

function getFieldLabel(field) {
    const label = document.querySelector(`label[for="${field.id}"]`);
    return label ? label.textContent.replace('*', '').trim() : field.name;
}

// ============================================
// ACCESSIBILITY UTILITIES
// ============================================

function announceToScreenReader(message) {
    const announcement = document.createElement('div');
    announcement.setAttribute('role', 'status');
    announcement.setAttribute('aria-live', 'polite');
    announcement.setAttribute('aria-atomic', 'true');
    announcement.className = 'sr-only';
    announcement.textContent = message;

    announcement.style.position = 'absolute';
    announcement.style.left = '-10000px';
    announcement.style.width = '1px';
    announcement.style.height = '1px';
    announcement.style.overflow = 'hidden';

    document.body.appendChild(announcement);

    setTimeout(() => {
        if (document.body.contains(announcement)) {
            document.body.removeChild(announcement);
        }
    }, 1000);
}

// ============================================
// PERFORMANCE MONITORING
// ============================================

if ('PerformanceObserver' in window) {
    const observer = new PerformanceObserver((list) => {
        list.getEntries().forEach((entry) => {
            if (entry.entryType === 'largest-contentful-paint') {
                console.log('LCP:', entry.startTime);
            }
            if (entry.entryType === 'first-input') {
                console.log('FID:', entry.processingStart - entry.startTime);
            }
        });
    });

    try {
        observer.observe({ entryTypes: ['largest-contentful-paint', 'first-input'] });
    } catch (e) {
        console.log('Performance observer not supported');
    }
}

// ============================================
// ERROR HANDLING
// ============================================

window.addEventListener('error', (e) => {
    console.error('JavaScript Error:', e.error);
});

// ============================================
// HERO VIDEO OPTIMIZATION
// ============================================

function initializeHeroVideo() {
    const video = document.querySelector('.hero-video-bg');
    if (!video) return;

    // Use Intersection Observer to pause video when not visible
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                video.play().catch(err => console.log("Auto-play prevented:", err));
                video.style.opacity = '0.55';
            } else {
                video.pause();
                video.style.opacity = '0';
            }
        });
    }, { threshold: 0.1 });

    observer.observe(video);

    // Performance optimization: Lower frame rate if battery is low (if supported)
    if ('getBattery' in navigator) {
        navigator.getBattery().then(battery => {
            if (battery.charging === false && battery.level < 0.2) {
                video.pause(); // Disable video on low battery to save power
            }
        });
    }
}

// Export utilities
window.WolfronixUtils = {
    announceToScreenReader
};

// ============================================
// ANIMATED PRICING SECTION
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    initializePricing();
});

function initializePricing() {
    const billingToggle = document.getElementById('billingToggle');
    const countrySelector = document.getElementById('countrySelector');
    const priceAmounts = document.querySelectorAll('.pricing-amount');
    const currencySymbols = document.querySelectorAll('.pricing-currency');
    const billingInfos = document.querySelectorAll('.pricing-billing-info');

    if (!billingToggle || !countrySelector) return;

    // Default Fallback Rates
    let exchangeRates = {
        'usd': 1, 'inr': 84.5, 'gbp': 0.79, 'eur': 0.92, 'jpy': 150.5
    };

    // Comprehensive Country Mapping
    const countryToCurrency = [
        { name: "United States", code: "usd", flag: "🇺🇸" },
        { name: "India", code: "inr", flag: "🇮🇳" },
        { name: "Eurozone", code: "eur", flag: "🇪🇺" },
        { name: "United Kingdom", code: "gbp", flag: "🇬🇧" },
        { name: "Japan", code: "jpy", flag: "🇯🇵" },
        { name: "Canada", code: "cad", flag: "🇨🇦" },
        { name: "Australia", code: "aud", flag: "🇦🇺" },
        { name: "Switzerland", code: "chf", flag: "🇨🇭" },
        { name: "China", code: "cny", flag: "🇨🇳" },
        { name: "Russia", code: "rub", flag: "🇷🇺" },
        { name: "Brazil", code: "brl", flag: "🇧🇷" },
        { name: "South Korea", code: "krw", flag: "🇰🇷" },
        { name: "Mexico", code: "mxn", flag: "🇲🇽" },
        { name: "South Africa", code: "zar", flag: "🇿🇦" },
        { name: "Turkey", code: "try", flag: "🇹🇷" },
        { name: "Sweden", code: "sek", flag: "🇸🇪" },
        { name: "Norway", code: "nok", flag: "🇳🇴" },
        { name: "Denmark", code: "dkk", flag: "🇩🇰" },
        { name: "Singapore", code: "sgd", flag: "🇸🇬" },
        { name: "New Zealand", code: "nzd", flag: "🇳🇿" },
        { name: "Hong Kong", code: "hkd", flag: "🇭🇰" },
        { name: "Thailand", code: "thb", flag: "🇹🇭" },
        { name: "Indonesia", code: "idr", flag: "🇮🇩" },
        { name: "Malaysia", code: "myr", flag: "🇲🇾" },
        { name: "Vietnam", code: "vnd", flag: "🇻🇳" },
        { name: "Philippines", code: "php", flag: "🇵🇭" },
        { name: "Taiwan", code: "twd", flag: "🇹🇼" },
        { name: "Saudi Arabia", code: "sar", flag: "🇸🇦" },
        { name: "UAE", code: "aed", flag: "🇦🇪" },
        { name: "Israel", code: "ils", flag: "🇮🇱" },
        { name: "Poland", code: "pln", flag: "🇵🇱" },
        { name: "Czech Republic", code: "czk", flag: "🇨🇿" },
        { name: "Hungary", code: "huf", flag: "🇭🇺" },
        { name: "Pakistan", code: "pkr", flag: "🇵🇰" },
        { name: "Bangladesh", code: "bdt", flag: "🇧🇩" },
        { name: "Sri Lanka", code: "lkr", flag: "🇱🇰" },
        { name: "Nepal", code: "npr", flag: "🇳🇵" },
        { name: "Argentina", code: "ars", flag: "🇦🇷" },
        { name: "Chile", code: "clp", flag: "🇨🇱" },
        { name: "Colombia", code: "cop", flag: "🇨🇴" },
        { name: "Peru", code: "pen", flag: "🇵🇪" },
        { name: "Egypt", code: "egp", flag: "🇪🇬" },
        { name: "Nigeria", code: "ngn", flag: "🇳🇬" },
        { name: "Kenya", code: "kes", flag: "🇰🇪" },
        { name: "Ukraine", code: "uah", flag: "🇺🇦" }
    ];

    // Populate Custom Dropdown
    function populateDropdown() {
        const dropdownOptions = document.getElementById('dropdownOptions');
        const selectedLabel = document.getElementById('selectedCountry');
        dropdownOptions.innerHTML = '';

        countryToCurrency.sort((a, b) => a.name.localeCompare(b.name));

        // Prioritize US, India, UK, Euro
        const priority = ['usd', 'inr', 'gbp', 'eur'];
        const priorityList = countryToCurrency.filter(c => priority.includes(c.code));
        const others = countryToCurrency.filter(c => !priority.includes(c.code));

        [...priorityList, ...others].forEach(c => {
            const div = document.createElement('div');
            div.className = 'dropdown-option';
            if (c.code === 'usd') div.classList.add('selected');
            div.dataset.value = c.code;
            div.innerHTML = `<span>${c.flag}</span> ${c.name} <span style="opacity:0.5; font-size: 0.8em; margin-left: auto;">${c.code.toUpperCase()}</span>`;

            div.addEventListener('click', (e) => {
                e.stopPropagation();

                // Update Value
                countrySelector.value = c.code;

                // Update Trigger Text
                selectedLabel.textContent = `${c.flag} ${c.name} (${c.code.toUpperCase()})`;

                // Active State
                document.querySelectorAll('.dropdown-option').forEach(el => el.classList.remove('selected'));
                div.classList.add('selected');

                // Close & Update
                document.getElementById('customCountryDropdown').classList.remove('open');
                updatePrices();
            });

            dropdownOptions.appendChild(div);
        });
    }
    populateDropdown();

    // Dropdown Interactions
    const customDropdown = document.getElementById('customCountryDropdown');
    const dropdownTrigger = document.getElementById('dropdownTrigger');

    if (customDropdown && dropdownTrigger) {
        dropdownTrigger.addEventListener('click', (e) => {
            e.stopPropagation();
            customDropdown.classList.toggle('open');
        });

        document.addEventListener('click', () => {
            customDropdown.classList.remove('open');
        });
    }

    // Fetch Live Rates (Fawaz Ahmed API)
    async function fetchRates() {
        // Build Helper for Fallback
        const tryFetch = async (url) => {
            const res = await fetch(url);
            if (!res.ok) throw new Error(`Failed to fetch from ${url}`);
            return await res.json();
        };

        try {
            console.log("Fetching live rates...");
            let data;

            try {
                // Primary: jsdelivr
                data = await tryFetch('https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json');
            } catch (e1) {
                console.warn("Primary API failed, trying fallback...", e1);
                // Fallback: pages.dev
                data = await tryFetch('https://latest.currency-api.pages.dev/v1/currencies/usd.json');
            }

            // The API returns { date: "...", usd: { "eur": 0.9, ... } }
            if (data && data.usd) {
                exchangeRates = { ...exchangeRates, ...data.usd };
                console.log("Live exchange rates updated.");
                updatePrices();
            }
        } catch (error) {
            console.error("All currency API attempts failed. Using static fallback.", error);
        }
    }

    fetchRates();

    function getCurrencySymbol(code) {
        const symbols = {
            'usd': '$', 'eur': '€', 'gbp': '£', 'inr': '₹', 'jpy': '¥', 'cad': 'C$', 'aud': 'A$',
            'cny': '¥', 'rub': '₽', 'krw': '₩', 'brl': 'R$', 'try': '₺', 'zar': 'R', 'ils': '₪',
            'php': '₱', 'thb': '฿', 'vnd': '₫', 'ngn': '₦', 'uah': '₴'
        };
        return symbols[code] || code.toUpperCase() + ' ';
    }

    function updatePrices() {
        const isYearly = billingToggle.checked;
        const currencyCode = countrySelector.value;
        const rate = exchangeRates[currencyCode] || 1;
        const symbol = getCurrencySymbol(currencyCode);

        // Update Symbols
        currencySymbols.forEach(el => el.textContent = symbol);

        // Update Prices
        priceAmounts.forEach(priceEl => {
            const baseMonthly = parseFloat(priceEl.dataset.monthly);
            const baseYearly = parseFloat(priceEl.dataset.yearly);

            let targetBasePrice = isYearly ? baseYearly : baseMonthly;
            let convertedPrice = targetBasePrice * rate;

            // Smart Formatting
            if (['jpy', 'krw', 'vnd', 'idr', 'clp', 'huf'].includes(currencyCode)) {
                convertedPrice = Math.round(convertedPrice / 100) * 100;
            } else if (['inr', 'rub', 'pkr', 'npr', 'lkr', 'bdt'].includes(currencyCode)) {
                convertedPrice = Math.round(convertedPrice / 10) * 10;
            } else {
                convertedPrice = Math.round(convertedPrice);
            }

            // Animate
            const currentVal = parseInt(priceEl.textContent.replace(/,/g, '')) || 0;
            if (currentVal !== convertedPrice) {
                priceEl.classList.add('animating');
                animateValue(priceEl, currentVal, convertedPrice, 500);
                setTimeout(() => priceEl.classList.remove('animating'), 500);
            }
        });

        // Billing Info
        billingInfos.forEach(info => {
            info.textContent = isYearly ? 'billed annually' : 'billed monthly';
        });

        if (isYearly) {
            // triggerConfetti() is handled in event listener
        }
    }

    // Event Listeners
    billingToggle.addEventListener('change', () => {
        updatePrices();
        if (billingToggle.checked) triggerConfetti();
    });

    countrySelector.addEventListener('change', () => {
        updatePrices();
    });
}

// Animate number transitions with smooth easing
function animateValue(element, start, end, duration) {
    const startTime = performance.now();

    const update = (currentTime) => {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Cubic ease-out for smooth deceleration
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const currentValue = Math.round(start + (end - start) * easeOut);

        element.textContent = currentValue.toLocaleString();

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    };

    requestAnimationFrame(update);
}

// Simple confetti effect
function triggerConfetti() {
    const canvas = document.getElementById('confettiCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const particles = [];
    const particleCount = 50;
    const colors = ['#0066FF', '#9333EA', '#00D9FF', '#10B981'];

    // Create particles
    for (let i = 0; i < particleCount; i++) {
        particles.push({
            x: window.innerWidth / 2,
            y: window.innerHeight / 2,
            r: Math.random() * 6 + 4,
            vx: (Math.random() - 0.5) * 10,
            vy: (Math.random() - 0.5) * 10 - 5,
            color: colors[Math.floor(Math.random() * colors.length)],
            gravity: 0.3,
            life: 100
        });
    }

    // Animate particles
    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        particles.forEach((p, index) => {
            if (p.life <= 0) {
                particles.splice(index, 1);
                return;
            }

            p.x += p.vx;
            p.y += p.vy;
            p.vy += p.gravity;
            p.life--;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = p.color;
            ctx.globalAlpha = p.life / 100;
            ctx.fill();
        });

        if (particles.length > 0) {
            requestAnimationFrame(animate);
        } else {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
        }
    }

    animate();
}

// Handle window resize for canvas
window.addEventListener('resize', () => {
    const canvas = document.getElementById('confettiCanvas');
    if (canvas) {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
});

// ============================================
// CONTACT FORM HANDLING
// ============================================

function initializeContactForm() {
    const contactForm = document.getElementById('contactForm');

    if (!contactForm) return;

    contactForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        // Get form data
        const formData = new FormData(contactForm);
        const data = Object.fromEntries(formData.entries());

        // Validate form fields
        if (!validateContactForm(data)) {
            return;
        }

        // Show loading state
        const submitButton = contactForm.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;
        submitButton.disabled = true;
        submitButton.innerHTML = `
            <span class="btn-text">SENDING...</span>
            <svg class="btn-lock" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
        `;

        try {
            // Submit form data to backend
            const response = await fetch('http://localhost:5000/api/contact', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });

            const result = await response.json();

            if (result.success) {
                // Show success message
                showNotification('Message sent successfully!', 'success');

                // Reset form
                contactForm.reset();
            } else {
                // Show error message
                showNotification(result.message || 'Failed to send message. Please try again.', 'error');
            }
        } catch (error) {
            console.error('Error submitting contact form:', error);
            showNotification('An error occurred. Please try again later.', 'error');
        } finally {
            // Restore button state
            submitButton.disabled = false;
            submitButton.innerHTML = originalButtonText;
        }
    });
}

function validateContactForm(data) {
    // Validate required fields
    if (!data.name || !data.name.trim()) {
        showNotification('Please enter your name', 'error');
        return false;
    }

    if (!data.email || !data.email.trim()) {
        showNotification('Please enter your email', 'error');
        return false;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
        showNotification('Please enter a valid email address', 'error');
        return false;
    }

    if (!data.message || !data.message.trim()) {
        showNotification('Please enter your message', 'error');
        return false;
    }

    return true;
}

function showNotification(message, type = 'info') {
    // Remove any existing notifications
    const existingNotification = document.querySelector('.notification-toast');
    if (existingNotification) {
        existingNotification.remove();
    }

    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'notification-toast';
    notification.innerHTML = `
        <div class="notification-content">
            <div class="notification-icon"></div>
            <div class="notification-message">${message}</div>
        </div>
    `;

    // Style the notification
    Object.assign(notification.style, {
        position: 'fixed',
        top: '20px',
        right: '20px',
        zIndex: '10000',
        backgroundColor: type === 'success' ? '#10B981' : type === 'error' ? '#EF4444' : '#3B82F6',
        color: 'white',
        padding: '16px 20px',
        borderRadius: '8px',
        boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
        maxWidth: '400px',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        fontFamily: 'Inter, sans-serif',
        fontSize: '14px',
        fontWeight: '500',
        transform: 'translateX(100%)',
        transition: 'transform 0.3s ease-out'
    });

    // Add to DOM
    document.body.appendChild(notification);

    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 10);

    // Auto-remove after delay
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 300);
    }, 5000);
}

// Initialize contact form when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    initializeContactForm();
});