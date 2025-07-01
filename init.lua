local http = require("coro-http")
local json = require("json")
local timer = require("timer")

local ropi = {
	cache = {
		users = {},
		avatars = {},
        groups = {}
	},
    cookie = nil
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
    if not iso then
        return
    end

	local year, month, day, hour, min, sec, ms = iso:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+).(%d+)Z")

	if not year or not month or not day or not hour or not min or not sec or not ms then
		return
	end
	
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

local function intoCache(item, category)
	for i = #ropi.cache[category],1,-1 do
		local u = ropi.cache[category][i]
		if u.id == item.id then
			table.remove(ropi.cache[category], i)
		end
	end

	table.insert(ropi.cache[category], item)

	return item
end

local function fromCache(query, category)
	for _, item in pairs(ropi.cache[category]) do
		if (type(query) == "string" and item.name:lower() == query:lower()) or (type(query) == "number" and item.id == query) then
			return item
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

local function GroupUser(data)
	return {
		name = data.username,
		displayName = data.displayName,
		id = data.userId,
		verified = not not data.hasVerifiedBadge,
		profile = "https://roblox.com/users/" .. data.userId .. "/profile",
		hyperlink = "[" .. data.username .. "](https://roblox.com/users/" .. data.userId .. "/profile)"
	}
end

local function Group(data)
	return {
		name = data.name,
		id = data.id,
		description = data.description,
		owner = ropi.GetUser(data.owner.userId),
		members = data.memberCount,
		shout = data.shout,
		verified = not not data.hasVerifiedBadge,
		public = not not data.publicEntryAllowed,
		link = "https://www.roblox.com/communities/" .. data.id,
		hyperlink = "[" .. data.name .. "](https://www.roblox.com/communities/" .. data.id ..")"
	}
end

local function Transaction(data)
    return {
        hash = data.idHash,
        created = fromISO(data.created),
        pending = data.isPending,
        user = ropi.GetUser(data.agent.id),
        item = {
            name = data.details.name,
            id = data.details.id,
            type = data.details.type,
            place = (data.details.place and {
                name = data.details.place.name,
                id = data.details.place.placeId,
                game = data.details.place.universeId
            }) or nil
        },
        price = data.currency.amount,
        token = data.purchaseToken
    }
end

local function Error(code, message)
	return {
		code = code,
		message = message
	}
end

-- request handler

function ropi:request(api, method, endpoint, headers, body, retryCount, version)
	retryCount = retryCount or 0
	
	if retryCount >= MAX_RETRIES then
		return false, Error(429, "The resource is being ratelimited.")
	end

    local url = "https://" .. api .. ".roblox.com/" .. (version or "v1") .. "/" .. endpoint

    headers = type(headers) == "table" and headers or {}
    if not hasHeader(headers, "Content-Type") then
		table.insert(headers, {"Content-Type", "application/json"})
	end

	body = (body and type(body) == "table" and json.encode(body)) or (type(body) == "string" and body) or nil

	local result, response = http.request(method, url, headers, body)
	response = (response and type(response) == "string" and json.decode(response)) or nil

	if result.code == 200 then
		RETRY_AFTER = 2000
		return true, response, result
	elseif result.code == 429 then
		print("[ROPI] | Retrying after " .. RETRY_AFTER .. "ms...")
		timer.sleep(RETRY_AFTER)
		RETRY_AFTER = RETRY_AFTER * 2
		
		return ropi:request(api, method, endpoint, headers, body, retryCount + 1, version)
	else
		return false, Error(result.code, result.reason), result
	end
end

-- api functions

function ropi.SetCookie(token)
    ropi.cookie = ".ROBLOSECURITY=" .. token

    return true
end

function ropi.GetToken()
    local _, _, result = ropi:request("itemconfiguration", "PATCH", "collectibles/xcsrftoken", {
        { "Cookie" , ropi.cookie }
    })

    for _, header in pairs(result) do
        if type(header) == "table" and type(header[1]) == "string" and header[1]:lower() == "x-csrf-token" then
			return true, header[2]
		end
    end

    return false, Error(500, "A token was not provided by the server.")
end

function ropi.GetAvatarHeadShot(id, opts, refresh)
	if type(id) ~= "string" and type(id) ~= "number" then
		return nil, Error(400, "An invalid ID was provided to GetAvatarHeadShot.")
	end
	
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
	if type(id) ~= "string" and type(id) ~= "number" then
		return nil, Error(400, "An invalid ID was provided to GetUser.")
	end
	
	if not refresh then
		local cached = fromCache(id, "users")
		if cached then
			return cached
		end
	end

	local success, user = ropi:request("users", "GET", "users/" .. id)

	if success and user and user.name and user.displayName and user.id then
		return intoCache(User(user), "users")
	else
		return nil, user
	end
end

function ropi.SearchUser(name, refresh)
	if type(name) ~= "string" and type(id) ~= "number" then
		return nil, Error(400, "An invalid name/ID was provided to SearchUser.")
	end
	
	if tonumber(name) then
		return ropi.GetUser(name, refresh)
	end
	
	if not refresh then
		local cached = fromCache(name, "users")
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

function ropi.GetGroup(id, refresh)
	if type(id) ~= "string" and type(id) ~= "number" then
		return nil, Error(400, "An invalid ID was provided to GetGroup.")
	end

	if not refresh then
		local cached = fromCache(id, "groups")
		if cached then
			return cached
		end
	end

	local success, group = ropi:request("groups", "GET", "groups/" .. id)

	if success and group and group.name and group.id then
		return intoCache(Group(group), "groups")
	else
		return nil, group
	end
end

function ropi.GetGroupMembers(id, full)
	local members = {}
	local cursor = nil

	repeat
		local url = "groups/" .. id .. "/users?limit=100" .. ((cursor and "&cursor=" .. cursor) or "")
		local success, response = ropi:request("groups", "GET", url)

		if success and response then
			for _, userdata in pairs(response.data or {}) do
				table.insert(members, (full and ropi.GetUser(userdata.user.userId)) or GroupUser(userdata.user))
			end

			cursor = response.nextPageCursor
		else
			break
		end
	until not cursor

	return true, members
end

function ropi.GetGroupTransactions(id, all)
    if not ropi.cookie then
        return nil, Error(400, ".ROBLOSECURITY cookie has not yet been set.")
    end

    local success, token = ropi.GetToken()

    if not success then
        return token
    end

    local transactions = {}
	local cursor = nil

	repeat
		local url = "groups/" .. id .. "/transactions?limit=100&transactionType=Sale" .. ((cursor and "&cursor=" .. cursor) or "")
		local success, response, result = ropi:request("economy", "GET", url, {
            {"Cookie", ropi.cookie},
            {"X-Csrf-Token", token}
        }, nil, nil, "v2")

		if success and response then
			for _, transactionData in pairs(response.data or {}) do
				table.insert(transactions, Transaction(transactionData))
			end

			cursor = response.nextPageCursor
		else
			break
		end
	until (not cursor) or (not all)

	table.sort(transactions, function(a, b)
		return a.created > b.created
	end)

    return transactions
end

function ropi.SetAssetPrice(collectibleID, price)
	if not ropi.cookie then
        return nil, Error(400, ".ROBLOSECURITY cookie has not yet been set.")
    end

    local success, token = ropi.GetToken()

    if not success then
        return token
    end

	if (not collectibleID) or type(collectibleID) ~= "string" then
		return nil, Error(400, "Collectible ID was not provided as a string.")
	elseif collectibleID:len() < 10 then
		return nil, Error(400, "A malformed collectible ID was provided.")
	end

	local success, response, result = ropi:request("itemconfiguration", "PATCH", "collectibles/" .. collectibleID, {
		{"Cookie", ropi.cookie},
		{"X-Csrf-Token", token}
	}, {
		saleLocationConfiguration = {
			saleLocationType = 1,
			places = {}
		},
		saleStatus = 0,
		quantityLimitPerUser = 0,
		resaleRestriction = 2,
		priceInRobux = price,
		priceOffset = 0,
		isFree = false
	})

	if success then
		return true
	else
		return false, result
	end
end

return ropi
