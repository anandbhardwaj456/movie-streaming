# 🎬 Magic Stream Movies : A Full-Stack Movie Streaming Platform with AI-Powered Recommendations

Magic Stream Movies is a full-stack web application built using **Go (Gin Gonic)**, **React**, **MongoDB**, and **OpenAI API**.  
It allows users to register, authenticate, explore movies, and receive intelligent movie recommendations powered by AI.

## 🚀 Steps to Run

1. **Clone the Repository**
    ```bash
    git clone https://github.com/raghuvansh-sahil/magic-stream-movies
    cd magic-stream-movies
    ```

2. **Backend Setup**
    1. Navigate to the server directory:
        ```bash
        cd server/magic-stream-movies-server
        ```

    2. Create a `.env` file inside this directory and add:
        ```
        DATABASE_NAME=magic-stream-movies
        MONGODB_URI=mongodb://localhost:27017/
        SECRET_KEY=<your_secret_key>
        SECRET_REFRESH_KEY=<your_secret_refresh_key>
        BASE_PROMPT_TEMPLATE=Return a response using one of these words: {rankings}. The response should be a single word and should not contain any other text. The response should be based on the following review:
        OPENAI_API_KEY=<your_openai_api_key>
        RECOMMENDED_MOVIE_LIMIT=5
        ALLOWED_ORIGINS=http://localhost:5173
        ```
        Replace `<your_secret_key>`, `<your_secret_refresh_key>`, `<your_openai_api_key>` with real values.

    3. Install dependencies and start the backend:
        ```bash
        go mod tidy
        go run .
        ```


    4. The backend will run on:
        👉 `http://localhost:8080`
<br>

3. **Frontend Setup**
    1. Open a new terminal and navigate to the client directory:
        ```bash
        cd client/magic-stream-movies-client
        ```

    2. Create a `.env` file inside this directory and add:
        ```
        VITE_API_BASE_URL=http://localhost:8080
        ```

    3. Install dependencies and start the frontend:
        ```bash
        npm install
        npm run dev
        ```

    4. The frontend will run on:
        👉 `http://localhost:5173`

## 🛠 API Endpoints

### 🔓 Unprotected Routes

| Method | Endpoint              | Description                              | Auth Required |
|--------|------------------------|-----------------------------------------|---------------|
| GET    | `/movies`             | Fetch all movies                         | ❌ No         |
| GET    | `/genres`             | Fetch list of movie genres               | ❌ No         |
| POST   | `/register`           | Register a new user                      | ❌ No         |
| POST   | `/login`              | User login                               | ❌ No         |
| POST   | `/logout`             | User logout                              | ❌ No         |
| POST   | `/refresh`            | Refresh access token using refresh token | ❌ No         |


### 🔐 Protected Routes

| Method | Endpoint                       | Description                                       | Auth Required |
|--------|--------------------------------|---------------------------------------------------|---------------|
| GET    | `/movie/:imdb_id`              | Fetch a movie by IMDb ID                          | ✅ Yes        |
| POST   | `/addmovie`                    | Add a movie to the database                       | 🚨 Admin Only |
| PATCH  | `/updatereview/:imdb_id`       | Update movie review                               | 🚨 Admin Only |
| GET    | `/recommendedmovies`           | Get AI-powered personalized movie recommendations | ✅ Yes        |

## 🙌 Credits

Huge thanks to [Gavin Lon](https://www.youtube.com/@GavinLon) for creating clear and practical full-stack development tutorial that guided me throughout this project.