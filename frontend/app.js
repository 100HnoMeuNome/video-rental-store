// API Configuration
const API_URL = 'http://localhost:5000';

// Check authentication status
function checkAuth() {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');

    if (token && user) {
        const userData = JSON.parse(user);
        const navLinks = document.getElementById('navLinks');
        const userNav = document.getElementById('userNav');
        const usernameDisplay = document.getElementById('usernameDisplay');

        if (navLinks) navLinks.style.display = 'none';
        if (userNav) userNav.style.display = 'flex';
        if (usernameDisplay) usernameDisplay.textContent = `Hello, ${userData.username}`;
    }
}

// Logout function
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = 'login.html';
}

// Load movies
async function loadMovies(search = '', genre = '') {
    try {
        let url = `${API_URL}/api/movies?`;
        if (search) url += `search=${encodeURIComponent(search)}&`;
        if (genre) url += `genre=${encodeURIComponent(genre)}&`;

        const response = await fetch(url);
        const data = await response.json();

        if (response.ok) {
            displayMovies(data.movies);
        } else {
            document.getElementById('moviesList').innerHTML = '<p class="error">Error loading movies</p>';
        }
    } catch (error) {
        document.getElementById('moviesList').innerHTML = '<p class="error">Error connecting to server</p>';
    }
}

// Display movies
function displayMovies(movies) {
    const container = document.getElementById('moviesList');

    if (movies.length === 0) {
        container.innerHTML = '<p>No movies found.</p>';
        return;
    }

    container.innerHTML = movies.map(movie => `
        <div class="movie-card">
            ${movie.posterUrl ? `<img src="${movie.posterUrl}" alt="${movie.title}">` : '<div class="no-poster">No Image</div>'}
            <h3>${movie.title}</h3>
            <p class="genre">${movie.genre} | ${movie.releaseYear}</p>
            <p class="description">${movie.description.substring(0, 100)}...</p>
            <p class="director"><strong>Director:</strong> ${movie.director}</p>
            <p class="rating"><strong>Rating:</strong> ${movie.rating}/10</p>
            <div class="pricing">
                <p><strong>Rent:</strong> $${movie.pricing.rent.toFixed(2)}</p>
                <p><strong>Buy:</strong> $${movie.pricing.buy.toFixed(2)}</p>
            </div>
            <p class="stock"><strong>Available:</strong> ${movie.stock.available} / ${movie.stock.total}</p>
            <div class="actions">
                <button onclick="rentOrBuy('${movie._id}', 'rent', ${movie.pricing.rent})"
                        ${movie.stock.available === 0 ? 'disabled' : ''}>
                    Rent
                </button>
                <button onclick="rentOrBuy('${movie._id}', 'buy', ${movie.pricing.buy})">
                    Buy
                </button>
            </div>
        </div>
    `).join('');
}

// Rent or buy movie - redirect to checkout page
async function rentOrBuy(movieId, type, price) {
    const token = localStorage.getItem('token');

    if (!token) {
        alert('Please login to rent or buy movies');
        window.location.href = 'login.html';
        return;
    }

    // Redirect to appropriate checkout page
    if (type === 'rent') {
        window.location.href = `rent-checkout.html?movieId=${movieId}`;
    } else if (type === 'buy') {
        window.location.href = `buy-checkout.html?movieId=${movieId}`;
    }
}
