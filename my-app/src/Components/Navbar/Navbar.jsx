import React, { useEffect, useState } from "react";
import './Navbar.css'
import logo from './youtube.png'
import SearchBar from "../SearchBar/SearchBar";
import { RiVideoAddLine } from 'react-icons/ri';
import { BiUserCircle } from 'react-icons/bi';
import { GoogleLogin } from 'react-google-login';
import { gapi } from "gapi-script"
import { IoMdNotificationsOutline } from "react-icons/io";
import { Link } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { login } from "../../actions/auth";
import Auth from "../../Pages/Auth/Auth";

function Navbar({ toggleDrawer, setEditCreateChanelBtn }) {
    const [AuthBtn, setAuthBtn] = useState(false)

    const CurrentUser = useSelector(state => state.currentUserReducer)
    console.log(CurrentUser)

    useEffect(() => {
        function start() {
            gapi.client.init({
                clientId: "553950956292-il0oclavg930tt024mrn3o5hgpgaot2n.apps.googleusercontent.com",
                scope: "email"
            })
        }
        gapi.load("client:auth2", start)
    }, []);

    const dispatch = useDispatch();
    const onSuccess = (response) => {
        const Email = response?.profileObj.email;
        console.log(Email);
        dispatch(login({ email: Email }))
    }

    const onFailure = (response) => {
        console.log("Failed", response)
    }

    return (
        <>
            <div className="Container_Navbar">
                <div className="Burger_Logo_Navbar">
                    <div className="burger" onClick={() => toggleDrawer()}>
                        <p></p>
                        <p></p>
                        <p></p>
                    </div>
                    <Link to={"/"} className="logo_div_Navbar">
                        <img src={logo} alt="" />
                        <p className="logo_title_navbar">YouTube</p>
                    </Link>
                </div>
                <SearchBar />
                <RiVideoAddLine size={22} className={"vid_bell_Navbar"} />
                <IoMdNotificationsOutline size={22} className={"vid_bell_Navbar"} />
                <div className="apps_Box">
                    {[...Array(9)].map((_, index) => (
                        <p key={index} className="appsBox"></p>
                    ))}
                </div>
                <div className="Auth_cont_Navbar">
                    {CurrentUser ? (
                        <>
                            <div className="Chanel_logo_App" onClick={() => setAuthBtn(true)}>
                                <p className="fstChar_logo_App">
                                    {CurrentUser?.result.name ? (
                                        <>
                                            {CurrentUser?.result.name.charAt(0).toUpperCase()}
                                        </>
                                    ) : (
                                        <>
                                            {CurrentUser?.result.email.charAt(0).toUpperCase()}
                                        </>
                                    )}
                                </p>
                            </div>
                        </>
                    ) : (
                        <>
                            <GoogleLogin
                                clientId={
                                    "553950956292-il0oclavg930tt024mrn3o5hgpgaot2n.apps.googleusercontent.com"
                                }
                                onSuccess={onSuccess}
                                onFailure={onFailure}
                                render={(renderProps) => (
                                    <p onClick={renderProps.onClick} className="Auth_Btn">
                                        <BiUserCircle size={22} />
                                        <b>Sign in</b>
                                    </p>
                                )}
                            />
                        </>
                    )}
                </div>
            </div>
            {AuthBtn &&
                <Auth
                    setEditCreateChanelBtn={setEditCreateChanelBtn}
                    setAuthBtn={setAuthBtn}
                    User={CurrentUser} />
            }
        </>
    );
}

export default Navbar;
