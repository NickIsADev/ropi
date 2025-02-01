local http = require("coro-http")
local json = require("json")
local timer = require("timer")

local ropi = {
	cache = {
		users = {},
		avatars = {}
	}
}

-- options

local RETRY_AFTER = 2000
local MAX_RETRIES = 3

-- general utilities

local function split(str, delim)
	local ret = {}
	if not str then
		return ret
	end
	if not delim or delim == '' then
		for c in string.gmatch(str, '.') do
			table.insert(ret, c)
		end
		return ret
	end
	local n = 1
	while true do
		local i, j = find(str, delim, n)
		if not i then break end
		table.insert(ret, sub(str, n, i - 1))
		n = j + 1
	end
	table.insert(ret, sub(str, n))
	return ret
end

local function hasHeader(headers, name)
	for _, header in pairs(headers) do
		if header[1]:lower() == name:lower() then
			return true
		end
	end
	
	return false
end

local function fromISO(iso)
	local year, month, day, hour, min, sec, ms = iso:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+).(%d+)Z")
	
	local epoch = os.time({
		year = tonumber(year),
		month = tonumber(month),
		day = tonumber(day),
		hour = tonumber(hour),
		min = tonumber(min),
		sec = tonumber(sec),
		isdst = false
	})
	
	return epoch + (tonumber(ms) / 1000)
end

-- cache utilities

local function intoCache(user)
	for i = #ropi.cache.users,1,-1 do
		local u = ropi.cache.users[i]
		if u.id == user.id then
			table.remove(ropi.cache.users, i)
		end
	end

	table.insert(ropi.cache.users, user)

	return user
end

local function fromCache(query)
	for _, u in pairs(ropi.cache.users) do
		if (type(query) == "string" and u.name:lower() == query:lower()) or (type(query) == "number" and u.id == query) then
			return u
		end
	end
end

-- objects

local function User(data)
	return {
		name = data.name,
		displayName = data.displayName,
		id = data.id,
		description = data.description,
		avatar = ropi.GetAvatarHeadShot(data.id),
		verified = not not data.hasVerifiedBadge,
		banned = not not data.isBanned,
		created = fromISO(data.created),
		profile = "https://roblox.com/users/" .. data.id .. "/profile",
		hyperlink = "[" .. data.name .. "](https://roblox.com/users/" .. data.id .. "/profile)"
	}
end

-- request handler

function ropi:request(api, method, endpoint, headers, body, retryCount)
	retryCount = retryCount or 0
	
	if retryCount >= MAX_RETRIES then
		return false, "The resource is being ratelimited."
	end

    local url = "https://" .. api .. ".roblox.com/v1/" .. endpoint

    headers = type(headers) == "table" and headers or {}
    if not hasHeader(headers, "Content-Type") then
		table.insert(headers, {"Content-Type", "application/json"})
	end

	body = (body and type(body) == "table" and json.encode(body)) or (type(body) == "string" and body) or nil

	local result, response = http.request(method, url, headers, body)
	response = (response and type(response) == "string" and json.decode(response)) or nil

	if result.code == 200 then
		RETRY_AFTER = 2000
		return true, response
	elseif result.code == 429 then
		print("[ROPI] | Retrying after " .. RETRY_AFTER .. "ms...")
		timer.sleep(RETRY_AFTER)
		RETRY_AFTER = RETRY_AFTER * 2
		
		return ropi:request(api, method, endpoint, headers, body, retryCount + 1)
	else
		return false, response or result
	end
end

-- api functions

function ropi.GetAvatarHeadShot(id, opts, refresh)
	opts = opts or {}
	id = tonumber(id) or 0

	if (not refresh) and ropi.cache.avatars[id] then
		return ropi.cache.avatars[id]
	end

	local options = {
		size = opts.size or 720,
		format = opts.format or "Png",
		isCircular = not not opts.isCircular
	}

	local success, response = ropi:request("thumbnails", "GET", "users/avatar-headshot?userIds=" .. id .. "&size=" .. options.size .. "x" .. options.size .. "&format=Png&isCircular=" .. tostring(options.isCircular))

	if success and response and response.data then
		if response.data[1] and response.data[1].state == "Completed" and response.data[1].imageUrl then
			ropi.cache.avatars[id] = response.data[1].imageUrl

			return response.data[1].imageUrl
		end
	end

	return nil, response
end

function ropi.GetUser(id, refresh)
	if not refresh then
		local cached = fromCache(id)
		if cached then
			return cached
		end
	end

	local success, user = ropi:request("users", "GET", "users/" .. id)

	if success and user and user.name and user.displayName and user.id then
		return intoCache(User(user))
	else
		return nil, user
	end
end

function ropi.SearchUser(name, refresh)
	if tonumber(name) then
		return ropi.GetUser(name, refresh)
	end
	
	if not refresh then
		local cached = fromCache(name)
		if cached then
			return cached
		end
	end

	local success, response = ropi:request("users", "POST", "usernames/users", nil, {
		usernames = {
			name
		},
		excludeBannedUsers = true
	})
	
	if success and response.data and response.data[1] and response.data[1].name and response.data[1].name:lower() == name:lower() and response.data[1].displayName and response.data[1].id then
		return ropi.GetUser(response.data[1].id)
	else
		return nil, response
	end
end

return ropi
