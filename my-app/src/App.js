import './App.css';
import React, { useState,useEffect } from 'react';
import Navbar from './Components/Navbar/Navbar';
import {
  BrowserRouter as Router,
} from 'react-router-dom';
import AllRoutes from './Components/AllRoutes';
import DrawerSidebar from './Components/LeftSideBar/DrawerSidebar';
import CreateEditChanel from './Pages/Chanel/CreateEditChanel';
import { useDispatch } from 'react-redux';
import { fetchAllChanel } from './actions/chanelUser';
import VideoUpload from './Pages/VideoUpload/VideoUpload';
import { getAllVideo } from './actions/video';
import { getAlllikedVideo } from './actions/likedVideo';
import { getAllwatchLater } from './actions/watchLater';
import { getAllHistroy } from './actions/Histroy';

function App() {
const dispatch=useDispatch()

useEffect(() =>{
  dispatch(fetchAllChanel());
  dispatch(getAllVideo());
  dispatch(getAlllikedVideo());
  dispatch(getAllwatchLater());
  dispatch(getAllHistroy());
},[dispatch])




  const [toggleDrawerSidebar, setToggleDrawerSidebar] = useState({
    display: "none",
  });

  const toggleDrawer = () => {
    if(toggleDrawerSidebar.display==="none"){
    setToggleDrawerSidebar({
      display:"flex"
    })
  }else{
    setToggleDrawerSidebar({
      display:"none"
    })
  }
  }
  
  const [videoUploadPage,setVideoUploadPage] = useState(false)
  const [EditCreateChanelBtn,setEditCreateChanelBtn] = useState(false)
  return (
    <Router>
      {
        videoUploadPage && <VideoUpload setVideoUploadPage ={setVideoUploadPage}/>}
      {
        EditCreateChanelBtn && <CreateEditChanel setEditCreateChanelBtn={setEditCreateChanelBtn}/>
      }
      <Navbar
      setEditCreateChanelBtn={setEditCreateChanelBtn}
      toggleDrawer={toggleDrawer} />
      <DrawerSidebar
        toggleDrawer={toggleDrawer}
        toggleDrawerSidebar={toggleDrawerSidebar}
      />
      <AllRoutes setVideoUploadPage ={setVideoUploadPage} setEditCreateChanelBtn={setEditCreateChanelBtn}/>
    </Router>
  );
}

export default App;
