// Вставь сюда свой ключ от VirusTotal
const VT_API_KEY = '8219c800083d4ea2e474503bca729183c0094ad0b841e7afabfa740a0f154109';

// 1. ГЕНЕРАТОР ПАРОЛЕЙ
function generateSafePassword() {
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
let password = "";
const values = new Uint32Array(16);
window.crypto.getRandomValues(values);
for (let i = 0; i < 16; i++) {
password += charset[values[i] % charset.length];
}
document.getElementById("password-output").innerText = password;
}

// 2. АНАЛИЗАТОР СЛОЖНОСТИ
document.getElementById('password-input').addEventListener('input', function(e) {
let pw = e.target.value;
let score = 0;

if (pw.length > 10) score += 25;
if (/[A-Z]/.test(pw)) score += 25;
if (/[0-9]/.test(pw)) score += 25;
if (/[^A-Za-z0-9]/.test(pw)) score += 25;

const bar = document.getElementById('strength-bar');
const feedback = document.getElementById('strength-feedback');

bar.style.width = score + "%";

if (score <= 25) { bar.style.background = "#ef4444"; feedback.innerText = "❌ Слишком слабый"; }
else if (score <= 50) { bar.style.background = "#f59e0b"; feedback.innerText = "⚠️ Средний пароль"; }
else if (score <= 75) { bar.style.background = "#3b82f6"; feedback.innerText = "✅ Хороший пароль"; }
else { bar.style.background = "#22c55e"; feedback.innerText = "🔒 Идеальная защита!"; }
});

// 3. ПРОВЕРКА ССЫЛОК (API VIRUSTOTAL)
async function analyzeLink() {
const urlToCheck = document.getElementById('url-input').value;
const feedbackBox = document.getElementById('url-feedback');

if (!urlToCheck) {
feedbackBox.innerHTML = "Введите ссылку!";
return;
}

feedbackBox.innerHTML = "🔍 Соединение с базой VirusTotal...";

try {
// Кодируем URL для API (Base64 без паддинга)
const encodedUrl = btoa(urlToCheck).replace(/=/g, "");

const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
method: 'GET',
headers: { 'x-apikey': VT_API_KEY }
});

if (!response.ok) throw new Error("Ошибка API (возможно, неверный ключ)");

const data = await response.json();
const stats = data.data.attributes.last_analysis_stats;

if (stats.malicious > 0) {
feedbackBox.style.color = "#ef4444";
feedbackBox.innerHTML = `🚨 ОПАСНО! Базы обнаружили угрозы: ${stats.malicious}. Не переходите по ссылке!`;
} else {
feedbackBox.style.color = "#22c55e";
feedbackBox.innerHTML = "✅ Чисто. Вредоносных программ в базе не обнаружено.";
}
} catch (err) {
feedbackBox.style.color = "#f59e0b";
feedbackBox.innerHTML = "❌ Ошибка: Ссылка новая или API ключ недействителен.";
}
}