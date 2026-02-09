
const API_BASE = "/api";

async function loadSubscriptionData() {
    const token = localStorage.getItem("token");
    if (!token) {
        window.location.href = "login.html";
        return;
    }

    try {
        // Fetch Me (Subscription & Usage)
        const res = await fetch(`${API_BASE}/subscription/me`, {
            headers: { Authorization: `Bearer ${token}` }
        });

        if (!res.ok) throw new Error("Failed to load subscription");

        const data = await res.json();
        const { subscription, paymentMethod } = data;
        const usage = subscription?.usage;

        // Populate Usage Cards
        if (usage) {
            // API Calls
            updateUsageCard('api', usage.apiCallsUsed, usage.apiCallsLimit, 'API Calls Used');

            // Users
            updateUsageCard('users', usage.seatsUsed, usage.seatsLimit, 'Active Users');
        }

        // Populate Billing Cycle
        if (subscription) {
            const nextDate = new Date(subscription.nextBillingDate);
            const today = new Date();
            const daysLeft = Math.ceil((nextDate - today) / (1000 * 60 * 60 * 24));

            const billingCard = document.querySelector('[data-card="billing"]');
            if (billingCard) {
                billingCard.querySelector('.text-2xl').textContent = `${daysLeft} days`;
                billingCard.querySelector('.text-xs.text-gray-500').textContent = `Renews: ${nextDate.toLocaleDateString()}`;
                const statusBadge = billingCard.querySelector('.text-xs.px-2');
                if (subscription.autoRenew) {
                    statusBadge.textContent = "Auto-renew ON";
                    statusBadge.className = "text-xs px-2 py-1 bg-green-500/10 text-green-400 rounded";
                } else {
                    statusBadge.textContent = "Auto-renew OFF";
                    statusBadge.className = "text-xs px-2 py-1 bg-red-500/10 text-red-400 rounded";
                }
            }
        }

        // Populate Payment Method
        if (paymentMethod) {
            document.querySelector('.glass-credit-card .text-2xl').textContent = `•••• •••• •••• ${paymentMethod.last4}`;
            document.querySelector('.glass-credit-card .font-medium.tracking-wide').textContent = paymentMethod.holder.toUpperCase();
            document.querySelectorAll('.glass-credit-card .font-medium.tracking-wide')[1].textContent = paymentMethod.expiry;

            const brandIcon = document.querySelector('.glass-credit-card .w-12');
            // Simple brand logic/color for demo
            if (paymentMethod.cardBrand.toLowerCase() === 'visa') {
                brandIcon.className = "w-12 h-8 bg-blue-900/50 rounded-md flex items-center justify-center text-white italic font-bold";
                brandIcon.textContent = "VISA";
            } else {
                brandIcon.className = "w-12 h-8 bg-red-900/50 rounded-md flex items-center justify-center text-white italic font-bold";
                brandIcon.textContent = "MC";
            }
        }

        // Fetch Invoices
        loadInvoices(token);

    } catch (error) {
        console.error("Load subscription error:", error);
    }
}

function updateUsageCard(type, used, limit, label) {
    const card = document.querySelector(`[data-card="${type}"]`);
    if (!card) return;

    const percentage = Math.round((used / limit) * 100);

    card.querySelector('.text-2xl').textContent = used.toLocaleString();
    card.querySelector('.text-xs.text-gray-500').textContent = `of ${limit.toLocaleString()}`;
    card.querySelector('.text-xs.font-semibold').textContent = `${percentage}%`;
    card.querySelector('.usage-bar').style.width = `${percentage}%`;
}

async function loadInvoices(token) {
    try {
        const res = await fetch(`${API_BASE}/subscription/invoices`, {
            headers: { Authorization: `Bearer ${token}` }
        });

        if (!res.ok) return;

        const invoices = await res.json();
        const container = document.querySelector('.bento-card .space-y-2'); // Targeting "Billing History" list

        if (container && invoices.length > 0) {
            container.innerHTML = invoices.map(inv => `
                <div class="flex items-center justify-between p-3 rounded-lg hover:bg-[#1E2530] transition group cursor-pointer border border-transparent hover:border-[#2D3748]">
                    <div class="flex items-center gap-4">
                        <div class="w-10 h-10 rounded-full bg-green-500/10 flex items-center justify-center text-green-500 border border-green-500/10">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                        </div>
                        <div>
                            <p class="text-sm text-white font-medium">${inv.description}</p>
                            <p class="text-xs text-gray-500">${new Date(inv.date).toLocaleDateString()} &bull; Invoice #${inv.id.toString().padStart(3, '0')}</p>
                        </div>
                    </div>
                    <div class="text-right">
                        <p class="text-sm text-white font-medium mb-0.5">$${inv.amount.toFixed(2)}</p>
                        <span class="text-[10px] text-blue-400 opacity-0 group-hover:opacity-100 transition uppercase tracking-wider font-semibold">Download PDF</span>
                    </div>
                </div>
            `).join('');
        }
    } catch (error) {
        console.error("Load invoices error:", error);
    }
}

document.addEventListener("DOMContentLoaded", loadSubscriptionData);
