# this method must be added in the sat_xor_differential_model.py library of CLAASP

    def find_one_lower_weight_xor_differential_trail_having_max_waist_time_bounded(
            self, minutes, fixed_values=[], solver_name=solvers.SOLVER_DEFAULT, options=None, start=None, autosave_immediate= True
    ):
        '''
        This method search for a trail and stop when find the optimal weight or when exceed 
        `minutes` consecutive minutes of SAT-solving without finding any other solution.
        The goal of this function is to search trail with a constraint on the searching time.
        It should be used when the actual optimal trail cannot be computed due to time-complexity.
        In general this function should find results close to the optimal (if the given time
        is enough for the given problem) but without waisting time (or at least not more than expected)
        to demonstrate the optimality (it has an exponential cost in term of weight and often cannot be
        computed, even thou we can find some good trail without getting stuck in non termination).
        This function will always terminate. The function terminates (after a variable amount of time)
        when it is no longer able to lower the weight of the trail within the `minutes` that we bound the solver to.

        This method can return:
        - None, in case it could not find any result without searching for more than `minutes` minutes
        - a trail with 'status': 'UNSATISFIABLE', in case it is certain that there is no trail with weight<=start
        - a trail with 'status': 'SATISFIABLE', sometimes it can be the optimal, in that case it will list 
            actual_solution["is_certainly_optimal"] = True, otherwise it might be optimal or close to it
        
        Parameters:    
        - autosave_immediate is a boolean that can enable temporary solution save. It is good to always have the 
          last founded result (even before completion) and to always have a trail even in case the SAT solver crashes.
        '''
        assert(start==None or (isinstance(start, int) and start >= 0))
        assert(minutes > 0)

        def remove_file(file_path):
            if file_path is None:
                return
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except:
                with open(f"error.log","a") as f:
                    f.write("Error removing "+file_path)
        
        def save_tmp_trail(actual_solution):
            if actual_solution is None:
                return
            file_path = f'find_one_lower_weight_xor_differential_trail__{actual_solution["cipher"]}_weight{int(actual_solution["total_weight"])}.tmp'
            try:
                with open(file_path,"w") as f:
                    f.write(str(actual_solution))
            except:
                with open(f"error.log","a") as f:
                    f.write("Error saving "+file_path)
            return file_path

        def find_one_lower_weight_trail(max_weight):
            assert(isinstance(start, int) and max_weight >= 0)
            start_building_time = time.time()
            self.build_xor_differential_trail_model(weight=max_weight, fixed_variables=fixed_values)
            end_building_time = time.time()
            solution = self.solve(XOR_DIFFERENTIAL, solver_name=solver_name, options=options)
            solution["building_time_seconds"] = end_building_time - start_building_time
            return solution

        def run_with_timeout(func, timeout, *args, **kwargs):
            """
            Run func(*args, **kwargs) in a separate process with a timeout (seconds).
            If the timeout expires, kill the subprocess *and all its children*
            (via process group).
            """

            q = multiprocessing.Queue()

            def wrapper(q, *a, **kw):
                try:
                    # Create a new session so that child and its subprocesses form an independent process group
                    os.setsid()
                    q.put(func(*a, **kw))
                except Exception as e:
                    q.put(e)

            p = multiprocessing.Process(target=wrapper, args=(q, *args), kwargs=kwargs)
            p.start()
            p.join(timeout)

            if p.is_alive():
                try:
                    pgid = os.getpgid(p.pid)
                    # Try to terminate
                    os.killpg(pgid, signal.SIGTERM)
                    time.sleep(2)
                    # Force kill if still alive
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    # Process may already have exited
                    pass
                finally:
                    p.terminate()
                    p.join(1)
                return None

            if q.empty():
                return None

            result = q.get()
            if isinstance(result, Exception):
                raise result
            return result

        def find_lower_weight_xor_differential_trail_within_timeout(start, timeout):         
            result = run_with_timeout(find_one_lower_weight_trail, timeout=timeout, max_weight=start)
            return result

        
        max_memory = 0
        waisted_time = 0
        solving_times = 0 

        # try to search a trail, better than start weight, from which to start
        a_trail = self.find_one_xor_differential_trail() # assume it's time << minutes*60
        a_weight = int(a_trail['total_weight'])
        solving_times+= a_trail["solving_time_seconds"]
        max_memory = max(max_memory, a_trail["memory_megabytes"])

        if start is not None and start < a_weight:
            current_weight = start
            actual_solution = None
        else:
            current_weight = a_weight - 1
            actual_solution = a_trail
            actual_solution["is_certainly_optimal"] = False # false by default

        # lower the limit until the search get stuck
        solution= find_lower_weight_xor_differential_trail_within_timeout(
            start=current_weight, 
            timeout= minutes*60 # the worst encountered case (you can waste at most minutes minutes)
        )
        if solution is None:
            waisted_time = minutes*60 
            if actual_solution is None:
                # it didn't find any acceptable solution within time, return no solution
                return None, "None"
            else:
                # case where it couldn't find any better solution within time, so return the actual_solution found
                actual_solution["is_certainly_optimal"] = False
        else:
            solving_times += solution["solving_time_seconds"]
            max_memory = max(max_memory, solution["memory_megabytes"])
            if solution["total_weight"] is None: # same as: solution['status'] == 'UNSATISFIABLE'
                if actual_solution is None:
                    # case where there is no trail with weight<=start, return unsatisfiable trail
                    return solution, "Unsat"
                else:
                    # case where there is no trail with weight lower than actual_solution, return actual_solution
                    actual_solution["is_certainly_optimal"] = True
        
        file_path = None
        while solution != None and solution["total_weight"] is not None:
            if autosave_immediate:
                remove_file(file_path)
            actual_solution = solution
            actual_solution["is_certainly_optimal"] = False
            if autosave_immediate:
                actual_solution["solving_time_seconds"] = solving_times + waisted_time
                actual_solution["memory_megabytes"] = max_memory
                actual_solution["test_name"] = "find_one_lower_weight_xor_differential_trail"
                file_path = save_tmp_trail(actual_solution)
            searched_weight = int(actual_solution['total_weight']) - 1
            
            if searched_weight < 0:
                # edge case where the optimal trail has weight 0
                actual_solution["is_certainly_optimal"] = True
                break
            
            t = minutes*60 
            solution = find_lower_weight_xor_differential_trail_within_timeout(
                start= searched_weight, 
                timeout= t # minutes minutes more than than the t.5 times the worst encountered case (you can waste at most minutes minutes)
            )
            if solution is None: #this happen in case of early interrupt before finding a solution
                waisted_time += t
                actual_solution["is_certainly_optimal"] = False
                break
            else:
                solving_times += solution["solving_time_seconds"]
                max_memory = max(max_memory, solution["memory_megabytes"])
                if solution["total_weight"] is None:
                    actual_solution["is_certainly_optimal"] = True
            
        actual_solution["solving_time_seconds"] = solving_times + waisted_time
        actual_solution["memory_megabytes"] = max_memory
        actual_solution["test_name"] = "find_one_lower_weight_xor_differential_trail"

        if autosave_immediate:
            remove_file(file_path)
            file_path = save_tmp_trail(actual_solution)

        # message to understand the behavior and if it can be optimized (print the necessaty time, the wasted time and the percentage of time not wasted)
        efficiency = round(100 * solving_times / (solving_times + waisted_time), 2)
        test_message = f"{round(solving_times+waisted_time, 2)}, {round(solving_times, 2)}, {round(waisted_time, 2)}, {efficiency}\n"
        
        assert(actual_solution is None or actual_solution['status'] == 'UNSATISFIABLE' or  actual_solution["total_weight"] >= 0)
        return actual_solution, test_message
