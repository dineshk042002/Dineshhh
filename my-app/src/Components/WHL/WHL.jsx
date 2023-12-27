import React from 'react'
import LeftSideBar from '../LeftSideBar/LeftSideBar'
import './WHLcss.css'
import WHLVideoList from './WHLVideoList'
import { useDispatch, useSelector } from 'react-redux';
import { clearHistroy } from '../../actions/Histroy';


function WHL({page,videoList}) {
    const CurrentUser = useSelector(state => state?.currentUserReducer);
    const dispatch=useDispatch()
    const handleClearHistroy=()=>{
        if(CurrentUser){
            dispatch(clearHistroy({
                userId:CurrentUser?.result._id
            }))
        }
    }
  return (
    <div className='Container_pages_App'>
        <LeftSideBar/>
        <div className='Container2_pages_App'>
            <p className='container_whl'>
                <div className='box_WhL leftside_whl'>
                    <b>Your {page} Shown Here </b>
                    {
                        page==="Histroy"&&
                    
                    <div className='clear_Histroy_btn' onClick={()=>handleClearHistroy()}>
                        Clear histroy
                    </div>
                    }
                </div>
                <div className='rightSide_whl'>
                    <h1>{page}</h1>
                    <div className='whl_list'>
                        <WHLVideoList
                        page={page}
                        CurrentUser={CurrentUser?.result._id}
                        videoList={videoList}/>
                    </div>
                </div>
            </p>
        </div>
    </div>
  )
}

export default WHL;