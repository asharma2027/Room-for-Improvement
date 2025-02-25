// Add these NEW functions at the bottom
// ========== FILTERING SYSTEM ==========
let currentDorm = '';
let currentHouse = '';

async function filterByDorm(dorm) {
  currentDorm = dorm;
  const houseSelect = document.getElementById('house-filter');
  
  // Fetch houses for selected dorm
  const response = await fetch(`/api/houses?dorm=${dorm}`);
  const houses = await response.json();
  
  // Populate house filter
  houseSelect.innerHTML = `
    <option value="">All Houses</option>
    ${houses.map(house => `<option value="${house}">${house}</option>`).join('')}
  `;
  houseSelect.disabled = false;
  
  loadFilteredRooms();
}

function filterByHouse(house) {
  currentHouse = house;
  loadFilteredRooms();
}

// Modified version of your existing loadRooms()
async function loadFilteredRooms() {
  const response = await fetch(`/api/rooms?dorm=${currentDorm}&house=${currentHouse}`);
  const rooms = await response.json();
  
  // Update the table with dorm/house columns
  const tableHTML = `
    <tr>
      <th>Room</th>
      <th>Dorm</th>
      <th>House</th>
      <th>Tags</th>
      <th>Scalars</th>
    </tr>
    ${rooms.map(room => `
      <tr onclick="window.location='/room/${room.id}'">
        <td>${room.number}</td>
        <td>${room.dorm}</td>
        <td>${room.house}</td>
        <td>${room.tags?.join(', ') || ''}</td>
        <td>${room.scalars?.join(', ') || ''}</td>
      </tr>
    `).join('')}
  `;
  
  document.getElementById('rooms-table').innerHTML = tableHTML;
}

// Initialize filters
document.addEventListener('DOMContentLoaded', () => {
  loadFilteredRooms();
});