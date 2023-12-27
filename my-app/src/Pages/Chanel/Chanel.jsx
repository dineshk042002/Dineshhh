import React, { useState } from "react";
import ShowVideoGrid from "../../Components/ShowVideoGrid/ShowVideoGrid";
import LeftSideBar from "../../Components/LeftSideBar/LeftSideBar";
import vid from '../../Components/Video/vid.mp4'
import DecribeChanel from "./DecribeChanel";
import { useParams } from "react-router-dom";
import { useSelector } from "react-redux";

function Chanel({setEditCreateChanelBtn,setVideoUploadPage}){
  const {Cid}=useParams();
  const vids = useSelector(state => state.videoReducer)?.data?.filter(q => q?.videoChanel === Cid).reverse();

        return (
            <div className='Container_pages_App'>
                <LeftSideBar/>
                <div className='Container2_pages_App'>
                  <DecribeChanel
                  Cid = {Cid}
                  setVideoUploadPage ={setVideoUploadPage}
                  setEditCreateChanelBtn={setEditCreateChanelBtn}/>
                  <ShowVideoGrid vids={vids}/>
                </div>
            </div>
          )
    
}
export default Chanel;