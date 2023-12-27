import React from 'react'
import './Home.css'
import { useSelector } from 'react-redux';
import LeftSideBar from '../../Components/LeftSideBar/LeftSideBar'
import ShowVideoGrid from '../../Components/ShowVideoGrid/ShowVideoGrid';
//import vid from '../../Components/Video/vid.mp4'

function Home() {


  const vids=useSelector(state=>state.videoReducer)?.data?.filter(q=>q).reverse();
  //console.log(videosFile)
  //
     const NavList=[
      "All",
      "python",
      "Java",
      "C++",
      "Android Development",
      ".Net",
      "Movies",
      "Science",
      "Games",
      "Animation",
      "Mathametics",
      "Comedy",
      "News",
      "Commerce",
      "Sports"
     ]
  return (
    <div className='Container_pages_App'>
        <LeftSideBar/>
        <div className='Container2_pages_App'>
          <div className='navigation_Home'>
            {
              NavList.map(m=>{
                return(
                <p key={m} className='btn_nav_home'>
                  {m}
                </p>)
              })
            }
          </div>
          <ShowVideoGrid vids={vids}/>
        </div>
    </div>
  )
}

export default Home