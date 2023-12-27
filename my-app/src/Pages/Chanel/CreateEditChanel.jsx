import React, { useState } from "react";
import './CreateEditChanel.css'
import { useDispatch, useSelector } from "react-redux";
import { login } from "../../actions/auth";
import { updateChanelDate } from "../../actions/chanelUser";
function CreateEditChanel({setEditCreateChanelBtn}){
    //const CurrentUser = {
    //    result:{
    //        email: "xyz@gmail.com",
    //        joinedOn: "2222-07-15T09:57:23.489Z",
    //    },
    // };
    const CurrentUser=useSelector(state=>state.currentUserReducer)
    const [name, setName] = useState(CurrentUser?.result.name)
    const [desc, setDesc] = useState(CurrentUser?.result.desc)
    const dispatch=useDispatch();
    const handleSubmit=()=>{
        if(!name){
            alert("Please Enter Name !");
        }else if(!desc){
            alert("Please Enter Description");
        }else{
            dispatch(updateChanelDate(CurrentUser?.result._id, {
                name:name,
                desc:desc,
            }));
            setEditCreateChanelBtn(false);
            setTimeout(()=>{
                dispatch(login({email: CurrentUser?.result.email}));
            }, 5000);
        }
    };
    return(
        <div className="container_CreateEditChanel">
            <input
            onClick={()=>setEditCreateChanelBtn(false)} 
            type="submit"
            name="date"
            value={"x"}
            className="ibtn_x" />
            <div className="container2_CreateEditChanel">
                <h1>{
                    CurrentUser?.result.name ?<>
                    Edit
                    </> :
                    <>Create</>
                    }
                    Your Channel</h1>
                    <input type="text"
                    name="text"
                    className="ibox"
                    placeholder="Enter your/Channel Name" 
                    value={name}
                    onChange={(e)=>setName(e.target.value)}
                    />
                    <textarea
                    type="text"
                    rows={15}
                    placeholder={"Enter Channel Description"}
                    className={"ibox"}
                    value={desc}
                    onChange={(e)=>setDesc(e.target.value)}
                    />
                    <input type="submit"
                    value={"Submit"}
                    onClick={handleSubmit}
                    className="ibtn" />
            </div>
        </div>
    )
}

export default CreateEditChanel