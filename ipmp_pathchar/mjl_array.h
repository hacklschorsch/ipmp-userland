#ifndef _MJL_ARRAY_H
#define _MJL_ARRAY_H

#include <sys/types.h>

typedef struct mjl_array mjl_array_t;
typedef int (*arraycompare_t)(const void **, const void **);
typedef int (*arrayclosest_t)(const void **, const void **, const void **);

mjl_array_t *array_create(int growby, arraycompare_t cmp);

int array_insert(mjl_array_t *array, void *ptr);
int array_compact(mjl_array_t *array);
int array_destroy(mjl_array_t *array, void (*destroy)(void *));
int array_remove(mjl_array_t *array, int from, int to);
int array_merge(mjl_array_t *a, mjl_array_t *b);

int array_quicksort(mjl_array_t *array);
#if defined(__FreeBSD__) || defined(__NetBSD__)
int array_heapsort(mjl_array_t *array);
#endif

int array_quicksort_using(mjl_array_t *array, arraycompare_t cmp);

void *array_find(mjl_array_t *array, void *ptr);
int   array_findclosest(mjl_array_t *array, void *ptr, arrayclosest_t closest);
void *array_find_using(mjl_array_t *array,  void *ptr, arraycompare_t compare);

#ifdef _THREAD_SAFE
int array_usemutexes(mjl_array_t *array, int useornot);
int array_trylock(mjl_array_t *array);
int array_lock(mjl_array_t *array);
int array_unlock(mjl_array_t *array);
#endif

void *array_getitem(mjl_array_t *array, int item);
void *array_getlastitem(mjl_array_t *array);
int array_getcount(mjl_array_t *array);

mjl_array_t *array_splitfromhere(mjl_array_t *array, void *ptr);

void array_print(mjl_array_t *array, int (*tostr)(void *,char *,size_t));
int  array_applyfunction(mjl_array_t *array, int (*function)(void *));

#endif /* _MJL_ARRAY_H */
