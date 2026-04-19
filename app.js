// Mock Data
const users = [
    { id: 1, name: 'Alex Wilber', upn: 'alexw@contoso.com', priority: 'High', insiderRisk: 'Elevated', status: 'Active', lastSeen: '2 mins ago', avatar: 'AW' },
    { id: 2, name: 'Megan Bowen', upn: 'meganb@contoso.com', priority: 'Low', insiderRisk: 'None', status: 'Active', lastSeen: '1 hour ago', avatar: 'MB' },
    { id: 3, name: 'Joni Sherman', upn: 'jonis@contoso.com', priority: 'Medium', insiderRisk: 'None', status: 'Blocked', lastSeen: '5 days ago', avatar: 'JS' },
    { id: 4, name: 'Isaiah Langer', upn: 'isaiahl@contoso.com', priority: 'High', insiderRisk: 'Critical', status: 'Active', lastSeen: '10 mins ago', avatar: 'IL' },
    { id: 5, name: 'Lynne Robbins', upn: 'lynner@contoso.com', priority: 'Low', insiderRisk: 'None', status: 'Active', lastSeen: '2 hours ago', avatar: 'LR' },
    { id: 6, name: 'Grady Archie', upn: 'gradya@contoso.com', priority: 'Medium', insiderRisk: 'Elevated', status: 'Active', lastSeen: '1 day ago', avatar: 'GA' },
    { id: 7, name: 'Patti Fernandez', upn: 'pattif@contoso.com', priority: 'Low', insiderRisk: 'None', status: 'Active', lastSeen: '3 hours ago', avatar: 'PF' },
    { id: 8, name: 'Nestor Wilke', upn: 'nestorw@contoso.com', priority: 'High', insiderRisk: 'Elevated', status: 'Active', lastSeen: 'Just now', avatar: 'NW' }
];

// Helper functions for rendering
function getPriorityBadge(priority) {
    if (priority === 'High') return `<span class="risk-badge risk-high"><i class="ph-fill ph-warning-circle"></i> ${priority}</span>`;
    if (priority === 'Medium') return `<span class="risk-badge risk-medium">${priority}</span>`;
    return `<span class="risk-badge risk-low">${priority}</span>`;
}

function getInsiderRiskBadge(risk) {
    if (risk === 'Critical') return `<span class="risk-badge risk-high"><i class="ph-fill ph-shield-warning"></i> ${risk}</span>`;
    if (risk === 'Elevated') return `<span class="risk-badge risk-medium">${risk}</span>`;
    return `<span class="risk-badge risk-low">${risk}</span>`;
}

function getStatusIndicator(status) {
    const statusClass = status === 'Active' ? 'status-active' : 'status-blocked';
    return `<div class="status-indicator ${statusClass}">
        <div class="status-dot"></div>
        <span>${status}</span>
    </div>`;
}

// DOM Elements
const tbody = document.getElementById('usersTableBody');
const searchInput = document.getElementById('userSearch');
const selectAllCheckbox = document.getElementById('selectAll');
const btnBlock = document.getElementById('btnBlock');
const btnReset = document.getElementById('btnReset');
const btnFilter = document.getElementById('btnFilter');
const btnExport = document.getElementById('btnExport');

// Profile DOM Elements
const usersListPage = document.getElementById('usersListPage');
const userProfilePage = document.getElementById('userProfilePage');
const backToUsersBtn = document.getElementById('backToUsersBtn');
const profileAvatar = document.getElementById('profileAvatar');
const profileName = document.getElementById('profileName');
const profileUpn = document.getElementById('profileUpn');
const profilePriority = document.getElementById('profilePriority');
const profileRisk = document.getElementById('profileRisk');
const profileStatus = document.getElementById('profileStatus');
const profileLastSeen = document.getElementById('profileLastSeen');

// State
let selectedRows = new Set();
let filteredUsers = [...users];

// Render Table
function renderTable() {
    tbody.innerHTML = '';
    
    if (filteredUsers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 32px; color: var(--ms-text-secondary);">No users found matching your search.</td></tr>`;
        return;
    }
    
    filteredUsers.forEach(user => {
        const isSelected = selectedRows.has(user.id);
        const tr = document.createElement('tr');
        if (isSelected) tr.classList.add('selected');
        
        tr.innerHTML = `
            <td><input type="checkbox" class="row-checkbox" data-id="${user.id}" ${isSelected ? 'checked' : ''}></td>
            <td>
                <div class="user-info">
                    <div class="user-avatar">${user.avatar}</div>
                    <span class="user-name">${user.name}</span>
                </div>
            </td>
            <td>${user.upn}</td>
            <td>${getPriorityBadge(user.priority)}</td>
            <td>${getInsiderRiskBadge(user.insiderRisk)}</td>
            <td>${getStatusIndicator(user.status)}</td>
            <td>${user.lastSeen}</td>
            <td><i class="ph ph-dots-three action-menu"></i></td>
        `;
        
        
        tbody.appendChild(tr);
        
        // Attach click listener for user profile
        tr.querySelector('.user-name').addEventListener('click', () => {
            openUserProfile(user);
        });
        
        // Attach click listener for action menu
        tr.querySelector('.action-menu').addEventListener('click', (e) => {
            e.stopPropagation();
            activeActionUserId = user.id;
            const rect = e.target.getBoundingClientRect();
            rowActionMenu.style.left = (rect.left - 120) + 'px';
            rowActionMenu.style.top = (rect.bottom + 8) + 'px';
            rowActionMenu.classList.add('show');
        });
    });
    
    attachCheckboxListeners();
    updateActionButtons();
}

// Event Listeners
function attachCheckboxListeners() {
    const checkboxes = document.querySelectorAll('.row-checkbox');
    checkboxes.forEach(cb => {
        cb.addEventListener('change', (e) => {
            const id = parseInt(e.target.dataset.id);
            if (e.target.checked) {
                selectedRows.add(id);
                e.target.closest('tr').classList.add('selected');
            } else {
                selectedRows.delete(id);
                e.target.closest('tr').classList.remove('selected');
            }
            updateSelectAllState();
            updateActionButtons();
        });
    });
}

selectAllCheckbox.addEventListener('change', (e) => {
    const checkboxes = document.querySelectorAll('.row-checkbox');
    if (e.target.checked) {
        filteredUsers.forEach(u => selectedRows.add(u.id));
        checkboxes.forEach(cb => {
            cb.checked = true;
            cb.closest('tr').classList.add('selected');
        });
    } else {
        selectedRows.clear();
        checkboxes.forEach(cb => {
            cb.checked = false;
            cb.closest('tr').classList.remove('selected');
        });
    }
    updateActionButtons();
});

function updateSelectAllState() {
    if (filteredUsers.length === 0) {
        selectAllCheckbox.checked = false;
        selectAllCheckbox.indeterminate = false;
        return;
    }
    
    const visibleSelectedCount = filteredUsers.filter(u => selectedRows.has(u.id)).length;
    
    if (visibleSelectedCount === 0) {
        selectAllCheckbox.checked = false;
        selectAllCheckbox.indeterminate = false;
    } else if (visibleSelectedCount === filteredUsers.length) {
        selectAllCheckbox.checked = true;
        selectAllCheckbox.indeterminate = false;
    } else {
        selectAllCheckbox.checked = false;
        selectAllCheckbox.indeterminate = true;
    }
}

function updateActionButtons() {
    const count = selectedRows.size;
    if (count > 0) {
        btnBlock.disabled = false;
        btnReset.disabled = false;
        
        if (count > 1) {
            btnBlock.innerHTML = `<i class="ph ph-prohibit"></i> Block sign-in (${count})`;
            btnReset.innerHTML = `<i class="ph ph-key"></i> Reset password (${count})`;
        } else {
            btnBlock.innerHTML = `<i class="ph ph-prohibit"></i> Block sign-in`;
            btnReset.innerHTML = `<i class="ph ph-key"></i> Reset password`;
        }
    } else {
        btnBlock.disabled = true;
        btnReset.disabled = true;
        btnBlock.innerHTML = `<i class="ph ph-prohibit"></i> Block sign-in`;
        btnReset.innerHTML = `<i class="ph ph-key"></i> Reset password`;
    }
}

// Filter logic
const filterDropdown = document.getElementById('filterDropdown');
const priorityCheckboxes = document.querySelectorAll('.filter-priority');
const riskCheckboxes = document.querySelectorAll('.filter-risk');
const statusCheckboxes = document.querySelectorAll('.filter-status');

function applyFilters() {
    const term = searchInput.value.toLowerCase();
    
    // Get checked filters
    const selectedPriorities = Array.from(priorityCheckboxes).filter(cb => cb.checked).map(cb => cb.value);
    const selectedRisks = Array.from(riskCheckboxes).filter(cb => cb.checked).map(cb => cb.value);
    const selectedStatuses = Array.from(statusCheckboxes).filter(cb => cb.checked).map(cb => cb.value);
    
    // Highlight button if any filter is active
    if (selectedPriorities.length > 0 || selectedRisks.length > 0 || selectedStatuses.length > 0) {
        btnFilter.style.backgroundColor = 'var(--ms-blue)';
        btnFilter.style.color = '#ffffff';
    } else {
        btnFilter.style.backgroundColor = '';
        btnFilter.style.color = '';
    }
    
    filteredUsers = users.filter(u => {
        const matchesSearch = u.name.toLowerCase().includes(term) || u.upn.toLowerCase().includes(term);
        const matchesPriority = selectedPriorities.length === 0 || selectedPriorities.includes(u.priority);
        const matchesRisk = selectedRisks.length === 0 || selectedRisks.includes(u.insiderRisk);
        const matchesStatus = selectedStatuses.length === 0 || selectedStatuses.includes(u.status);
        return matchesSearch && matchesPriority && matchesRisk && matchesStatus;
    });
    
    // Re-apply sorting if active
    if (sortCol) {
        const priorityWeight = { 'High': 3, 'Medium': 2, 'Low': 1, 'None': 0 };
        const riskWeight = { 'Critical': 3, 'Elevated': 2, 'None': 1 };
        
        filteredUsers.sort((a, b) => {
            let valA = a[sortCol];
            let valB = b[sortCol];
            
            if (sortCol === 'priority') {
                valA = priorityWeight[valA] || 0;
                valB = priorityWeight[valB] || 0;
            } else if (sortCol === 'insiderRisk') {
                valA = riskWeight[valA] || 0;
                valB = riskWeight[valB] || 0;
            } else if (sortCol === 'lastSeen') {
                const parseDate = (s) => {
                    if (s === 'Just now') return 0;
                    const match = s.match(/(\d+)\s+(min|hour|day)/);
                    if (!match) return 999999;
                    const val = parseInt(match[1]);
                    if (match[2].includes('min')) return val;
                    if (match[2].includes('hour')) return val * 60;
                    if (match[2].includes('day')) return val * 60 * 24;
                    return 999999;
                };
                valA = parseDate(valA);
                valB = parseDate(valB);
            } else {
                if (typeof valA === 'string') valA = valA.toLowerCase();
                if (typeof valB === 'string') valB = valB.toLowerCase();
            }
            
            if (valA < valB) return sortAsc ? -1 : 1;
            if (valA > valB) return sortAsc ? 1 : -1;
            return 0;
        });
        
        // sync UI icons on table headers
        document.querySelectorAll('.sortable i').forEach(i => {
            i.className = 'ph ph-arrows-down-up';
            i.style.opacity = '0.5';
        });
        const activeTh = document.querySelector(`.sortable[data-sort="${sortCol}"]`);
        if (activeTh) {
            const icon = activeTh.querySelector('i');
            icon.className = sortAsc ? 'ph ph-caret-up' : 'ph ph-caret-down';
            icon.style.opacity = '1';
        }
    }
    
    renderTable();
    updateSelectAllState();
}

const globalSearch = document.getElementById('globalSearch');
if (globalSearch) {
    globalSearch.addEventListener('input', (e) => {
        searchInput.value = e.target.value;
        applyFilters();
    });
}
searchInput.addEventListener('input', (e) => {
    if (globalSearch) globalSearch.value = e.target.value;
    applyFilters();
});
priorityCheckboxes.forEach(cb => cb.addEventListener('change', applyFilters));
riskCheckboxes.forEach(cb => cb.addEventListener('change', applyFilters));
statusCheckboxes.forEach(cb => cb.addEventListener('change', applyFilters));

// Action button handlers
btnBlock.addEventListener('click', () => {
    alert(`Blocking sign-in for ${selectedRows.size} user(s).`);
    // Simulated action
    filteredUsers.forEach(u => {
        if (selectedRows.has(u.id)) {
            u.status = 'Blocked';
        }
    });
    selectedRows.clear();
    renderTable();
    updateSelectAllState();
});

btnReset.addEventListener('click', () => {
    alert(`Initiating password reset for ${selectedRows.size} user(s).`);
});

// Sorting State
let sortCol = 'name';
let sortAsc = true;

const btnSort = document.getElementById('btnSort');
const sortDropdown = document.getElementById('sortDropdown');
const sortColRadios = document.querySelectorAll('input[name="sortCol"]');
const sortOrderRadios = document.querySelectorAll('input[name="sortOrder"]');

// Sort Dropdown Toggle
btnSort.addEventListener('click', (e) => {
    e.stopPropagation();
    sortDropdown.classList.toggle('show');
});

sortDropdown.addEventListener('click', (e) => {
    e.stopPropagation();
});

document.addEventListener('click', (e) => {
    if (!sortDropdown.contains(e.target) && e.target !== btnSort) {
        sortDropdown.classList.remove('show');
    }
});

// Sync radio buttons to variables
function updateSortFromRadios() {
    const colRadio = document.querySelector('input[name="sortCol"]:checked');
    const orderRadio = document.querySelector('input[name="sortOrder"]:checked');
    if (colRadio) sortCol = colRadio.value;
    if (orderRadio) sortAsc = (orderRadio.value === 'asc');
    
    btnSort.style.backgroundColor = 'var(--ms-blue)';
    btnSort.style.color = '#ffffff';
    applyFilters();
}

sortColRadios.forEach(r => r.addEventListener('change', updateSortFromRadios));
sortOrderRadios.forEach(r => r.addEventListener('change', updateSortFromRadios));

// Clickable Table Headers
document.querySelectorAll('.sortable').forEach(th => {
    th.addEventListener('click', () => {
        const col = th.dataset.sort;
        if (sortCol === col) {
            sortAsc = !sortAsc;
        } else {
            sortCol = col;
            sortAsc = true;
        }
        
        // Sync radios
        const colR = document.querySelector(`input[name="sortCol"][value="${col}"]`);
        if (colR) colR.checked = true;
        const ordR = document.querySelector(`input[name="sortOrder"][value="${sortAsc ? 'asc' : 'desc'}"]`);
        if (ordR) ordR.checked = true;
        
        updateSortFromRadios();
    });
});

// Filtering Logic (Dropdown Toggle)
btnFilter.addEventListener('click', (e) => {
    e.stopPropagation();
    filterDropdown.classList.toggle('show');
});

filterDropdown.addEventListener('click', (e) => {
    e.stopPropagation(); // Prevent closing when clicking inside
});

document.addEventListener('click', (e) => {
    if (!filterDropdown.contains(e.target) && e.target !== btnFilter) {
        filterDropdown.classList.remove('show');
    }
});

// Export Logic
btnExport.addEventListener('click', () => {
    if (filteredUsers.length === 0) {
        alert("No data to export.");
        return;
    }
    const headers = ["Display Name", "User Principal Name", "Investigation Priority", "Insider Risk", "Status", "Last Seen"];
    const csvRows = [headers.join(',')];
    
    filteredUsers.forEach(u => {
        csvRows.push(`${u.name},${u.upn},${u.priority},${u.insiderRisk},${u.status},${u.lastSeen}`);
    });
    
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.setAttribute('hidden', '');
    a.setAttribute('href', url);
    a.setAttribute('download', 'Defender_Users_Export.csv');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
});

// Initialize
renderTable();

// User Profile Logic
function openUserProfile(user) {
    // Populate data
    profileAvatar.textContent = user.avatar;
    profileName.textContent = user.name;
    profileUpn.textContent = user.upn;
    profilePriority.innerHTML = getPriorityBadge(user.priority);
    profileRisk.innerHTML = getInsiderRiskBadge(user.insiderRisk);
    profileStatus.innerHTML = getStatusIndicator(user.status);
    profileLastSeen.textContent = user.lastSeen;
    
    // Switch view
    usersListPage.style.display = 'none';
    userProfilePage.style.display = 'block';
}

backToUsersBtn.addEventListener('click', () => {
    userProfilePage.style.display = 'none';
    usersListPage.style.display = 'block';
});

// Row Action Logic
const rowActionMenu = document.getElementById('rowActionMenu');
const actionDetails = document.getElementById('actionDetails');
const actionDisable = document.getElementById('actionDisable');
let activeActionUserId = null;

document.addEventListener('click', () => {
    if (rowActionMenu) rowActionMenu.classList.remove('show');
});

actionDetails.addEventListener('click', () => {
    const user = users.find(u => u.id === activeActionUserId);
    if(user) openUserProfile(user);
});

actionDisable.addEventListener('click', () => {
    const user = users.find(u => u.id === activeActionUserId);
    if(user) alert(`Disabled account for ${user.name}`);
});

// Settings & Theme Logic
const btnSettings = document.getElementById('btnSettings');
const settingsModal = document.getElementById('settingsModal');
const closeSettings = document.getElementById('closeSettings');
const themeRadios = document.querySelectorAll('input[name="themeMode"]');
const mobileToggle = document.getElementById('mobileViewToggle');

btnSettings.addEventListener('click', (e) => {
    e.preventDefault();
    settingsModal.style.display = 'flex';
});

closeSettings.addEventListener('click', () => {
    settingsModal.style.display = 'none';
});

function applyTheme(themeValue) {
    document.body.className = document.body.className.replace(/theme-\w+/g, '');
    if (themeValue !== 'dark') {
        document.body.classList.add('theme-' + themeValue);
    }
    localStorage.setItem('defenderTheme', themeValue);
    const activeRadio = document.querySelector(`input[name="themeMode"][value="${themeValue}"]`);
    if(activeRadio) activeRadio.checked = true;
}

themeRadios.forEach(r => {
    r.addEventListener('change', (e) => {
        applyTheme(e.target.value);
    });
});

function applyMobileView(isMobile) {
    if (isMobile) document.body.classList.add('mobile-view');
    else document.body.classList.remove('mobile-view');
    localStorage.setItem('defenderMobileView', isMobile);
    mobileToggle.checked = isMobile;
}

mobileToggle.addEventListener('change', (e) => {
    applyMobileView(e.target.checked);
});

// Load saved settings on startup
const savedTheme = localStorage.getItem('defenderTheme') || 'dark';
applyTheme(savedTheme);

const savedMobileView = localStorage.getItem('defenderMobileView') === 'true';
applyMobileView(savedMobileView);

// Top Header Actions
const btnHelp = document.getElementById('btnHelp');
const helpMenu = document.getElementById('helpMenu');

const btnNotifications = document.getElementById('btnNotifications');
const notifMenu = document.getElementById('notifMenu');

const btnProfile = document.getElementById('btnProfile');
const profileMenu = document.getElementById('profileMenu');

if (btnHelp) btnHelp.addEventListener('click', (e) => { e.stopPropagation(); helpMenu.classList.toggle('show'); });
if (btnNotifications) btnNotifications.addEventListener('click', (e) => { e.stopPropagation(); notifMenu.classList.toggle('show'); });
if (btnProfile) btnProfile.addEventListener('click', (e) => { e.stopPropagation(); profileMenu.classList.toggle('show'); });

document.addEventListener('click', (e) => {
    if (helpMenu && !helpMenu.contains(e.target) && e.target !== btnHelp) helpMenu.classList.remove('show');
    if (notifMenu && !notifMenu.contains(e.target) && e.target !== btnNotifications) notifMenu.classList.remove('show');
    if (profileMenu && !profileMenu.contains(e.target) && e.target !== btnProfile) profileMenu.classList.remove('show');
});

// Sidebar Toggle Logic
const btnSidebarToggle = document.getElementById('btnSidebarToggle');
function applySidebarState(isCollapsed) {
    if (isCollapsed) document.body.classList.add('sidebar-collapsed');
    else document.body.classList.remove('sidebar-collapsed');
    localStorage.setItem('defenderSidebarCollapsed', isCollapsed);
}

if (btnSidebarToggle) {
    btnSidebarToggle.addEventListener('click', () => {
        const isCurrentlyCollapsed = document.body.classList.contains('sidebar-collapsed');
        applySidebarState(!isCurrentlyCollapsed);
    });
}

// Load saved sidebar state
const savedSidebarState = localStorage.getItem('defenderSidebarCollapsed') === 'true';
applySidebarState(savedSidebarState);
