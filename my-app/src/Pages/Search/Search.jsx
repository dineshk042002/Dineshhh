import React from 'react'
//import './Home.css'
import { useSelector } from 'react-redux';
import LeftSideBar from '../../Components/LeftSideBar/LeftSideBar'
import ShowVideoGrid from '../../Components/ShowVideoGrid/ShowVideoGrid';
import { useParams } from 'react-router-dom';
//import vid from '../../Components/Video/vid.mp4'

function Search() {


    const {searchQuery}=useParams();
  const vids=useSelector(state=>state.videoReducer)
  ?.data?.filter((q)=> q?.videoTitle.toUpperCase().includes(searchQuery.toUpperCase())).reverse();
  //console.log(videosFile)
  
     
  return (
    <div className='Container_pages_App'>
        <LeftSideBar/>
        <div className='Container2_pages_App'>
            <h2 style={{color:"white"}}>Search Results for  {searchQuery}....</h2>
          <ShowVideoGrid vids={vids}/>
        </div>
    </div>
  );
}

export default Search