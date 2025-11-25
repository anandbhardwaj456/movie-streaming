import './App.css'
import Home from './components/home/Home'
import Recommended from './components/recommended/Recommended'
import Header from './components/header/Header'
import Register from './components/register/Register'
import Login from './components/login/Login'
import Review from './components/review/Review'
import Layout from './components/Layout'
import RequiredAuth from './components/RequiredAuth'
import axiosClient from './api/axiosConfig'
import useAuth from './hooks/useAuth'
import { Route, Routes, useNavigate } from 'react-router-dom'
import StreamMovie from './components/stream/StreamMovie'


function App() {
  const navigate = useNavigate()
  const {auth, setAuth} = useAuth();

  const updateMovieReview = (imdb_id) => {
    navigate(`/review/${imdb_id}`)
  }

  const handleLogout = async () => {
    try {
      const response = await axiosClient.post("/logout", {user_id: auth.user_id})
      setAuth(null)
    } catch (error) {
      console.error("Error logging out: ", error)
    }
  }

  return (
    <>
      <Header handleLogout={handleLogout}/>
      <Routes>
        <Route path="/" element={<Layout/>}>
          <Route index element={<Home updateMovieReview={updateMovieReview}/>}></Route>
          <Route path="/register" element={<Register/>}></Route>
          <Route path="/login" element={<Login/>}></Route>

          <Route element={<RequiredAuth/>}>
            <Route path="/recommended" element={<Recommended/>}></Route>
            <Route path="/review/:imdb_id" element={<Review/>}></Route>
            <Route path="/stream/:yt_id" element={<StreamMovie/>}></Route>
          </Route>
        </Route>
      </Routes>
    </>
  )
}

export default App