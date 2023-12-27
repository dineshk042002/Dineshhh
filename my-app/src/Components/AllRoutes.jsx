import React from 'react'
import Home from '../Pages/Home/Home'

import {
    Routes,
    Route
    
  } from "react-router-dom";
import Library from '../Pages/Library/Library';
import LikedVideo from '../Pages/LikedVideo/LikedVideo';
import WatchHistroy from '../Pages/WatchHistroy/WatchHistroy';
import WatchLater from '../Pages/WatchLater/WatchLater';
import YourVideo from '../Pages/YourVideo/YourVideo';
import VideoPage from '../Pages/VideoPage/VideoPage';
import Chanel from '../Pages/Chanel/Chanel';
import Search from '../Pages/Search/Search';
function AllRoutes({setEditCreateChanelBtn,setVideoUploadPage}) {
  return (
    <Routes>
        <Route path='/' element={<Home/>}/>
        <Route path='/library' element={<Library/>}/>
        <Route path='/LikedVideo' element={<LikedVideo/>}/>
        <Route path='/WatchHistroy' element={<WatchHistroy/>}/>
        <Route path='/WatchLater' element={<WatchLater/>}/>
        <Route path='/YourVideo' element={<YourVideo/>}/>
        <Route path='/VideoPage/:vid' element={<VideoPage/>}/>
        <Route path='/Search/:searchQuery' element={<Search/>}/>
        <Route path='/Chanel/:Cid' 
        element={<Chanel 
          setVideoUploadPage ={setVideoUploadPage}
          setEditCreateChanelBtn={setEditCreateChanelBtn}/>}
        />
    </Routes>
  );
}

export default AllRoutes;