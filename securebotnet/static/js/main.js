document.addEventListener('DOMContentLoaded', function() {
    initializeTooltips();
    initializeDropdowns();
});

function initializeTooltips() {
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipTriggerList.forEach(el => new bootstrap.Tooltip(el));
}

function initializeDropdowns() {
    const dropdownElementList = document.querySelectorAll('.dropdown-toggle');
    dropdownElementList.forEach(el => new bootstrap.Dropdown(el));
}

function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

function showNotification(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 80px; right: 20px; z-index: 9999; min-width: 300px;';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

function getChartColors() {
    return {
        primary: '#667eea',
        success: '#28a745',
        danger: '#dc3545',
        warning: '#ffc107',
        info: '#17a2b8',
        secondary: '#6c757d'
    };
}

window.formatNumber = formatNumber;
window.showNotification = showNotification;
window.getChartColors = getChartColors;
